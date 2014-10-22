#include <stdlib.h>
#include <curl/curl.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <uv.h>

#include "vrt.h"
#include "vsb.h"
#include "cache/cache.h"

#include "vcc_if.h"
#include "config.h"

struct hdr {
	char *key;
	char *value;
	VTAILQ_ENTRY(hdr) list;
};

struct req_hdr {
	char *value;
	VTAILQ_ENTRY(req_hdr) list;
};

struct vmod_curl {
	unsigned magic;
#define VMOD_CURL_MAGIC 0xBBB0C87C
	unsigned vxid;
	long status;
	long timeout;
	long connect_timeout;
	char flags;
#define F_SSL_VERIFY_PEER	(1 << 0)
#define F_SSL_VERIFY_HOST	(1 << 1)
#define F_METHOD_GET		(1 << 2)
#define F_METHOD_HEAD		(1 << 3)
#define F_METHOD_POST		(1 << 4)
	const char *url;
	const char *method;
	const char *postfields;
	const char *error;
	const char *cafile;
	const char *capath;
	VTAILQ_HEAD(, hdr) headers;
	VTAILQ_HEAD(, req_hdr) req_headers;
	const char *proxy;
	struct vsb *body;
	int no_wait;
	int performing;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
};

/* The libuv socket event context */
struct socket_context {
	unsigned magic;
#define VMOD_SOCKET_CONTEXT_MAGIC 0xBBB0C87D
	uv_poll_t poll_handle;
	curl_socket_t sockfd;
};

/* the curl easy call context */
struct curl_context {
	unsigned magic;
#define VMOD_CURL_CONTEXT_MAGIC 0xBBB0C87E
	struct vmod_curl *c;
	struct curl_slist *req_headers;
};

static int initialised = 0;

static struct vmod_curl **vmod_curl_list;
int vmod_curl_list_sz;
static pthread_mutex_t cl_mtx = PTHREAD_MUTEX_INITIALIZER;

/* the libuv event loop related stuff */
static pthread_mutex_t gl_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gl_cond = PTHREAD_COND_INITIALIZER;
static uv_loop_t *loop;
static uv_timer_t timeout;
static uv_async_t async;
static int callback_running = 0;

/* the singleton CURL multi handle */
static CURLM *multi_handle;

static void cm_clear(struct vmod_curl *c);

static void start_event_loop(void);

static void
cm_init(struct vmod_curl *c)
{
	c->magic = VMOD_CURL_MAGIC;
	VTAILQ_INIT(&c->headers);
	VTAILQ_INIT(&c->req_headers);
	c->body = VSB_new_auto();
	cm_clear(c);
	AZ(pthread_mutex_init(&c->mtx, NULL));
	AZ(pthread_cond_init(&c->cond, NULL));
	c->performing = 0;
	c->no_wait = 0;
}

static void
cm_clear_body(struct vmod_curl *c)
{
	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	VSB_clear(c->body);
}

static void
cm_clear_headers(struct vmod_curl *c)
{
	struct hdr *h, *h2;

	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	VTAILQ_FOREACH_SAFE(h, &c->headers, list, h2) {
		VTAILQ_REMOVE(&c->headers, h, list);
		free(h->key);
		free(h->value);
		free(h);
	}
}

static void
cm_clear_req_headers(struct vmod_curl *c)
{
	struct req_hdr *rh, *rh2;

	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	VTAILQ_FOREACH_SAFE(rh, &c->req_headers, list, rh2) {
		VTAILQ_REMOVE(&c->req_headers, rh, list);
		free(rh->value);
		free(rh);
	}
}

static void
cm_clear_fetch_state(struct vmod_curl *c)
{
	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	c->flags &= ~(F_METHOD_GET | F_METHOD_HEAD | F_METHOD_POST);
	cm_clear_body(c);
	cm_clear_headers(c);
}

static void
cm_clear(struct vmod_curl *c)
{
	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	cm_clear_fetch_state(c);

	c->connect_timeout = -1;
	c->timeout = -1;
	c->cafile = NULL;
	c->capath = NULL;
	c->error = NULL;
	c->flags = 0;
	c->method = NULL;
	c->proxy = NULL;
	c->status = 0;
	c->vxid = 0;
	c->no_wait = 0;
}

static struct vmod_curl *
cm_get_reserve(const struct vrt_ctx *ctx, int reserve_for_call)
{
	struct vmod_curl *cm;

	AZ(pthread_mutex_lock(&cl_mtx));

	while (vmod_curl_list_sz <= ctx->req->sp->fd) {
		int ns = vmod_curl_list_sz * 2;
		/* resize array */
		vmod_curl_list =
		    realloc(vmod_curl_list, ns * sizeof(struct vmod_curl *));
		for (; vmod_curl_list_sz < ns; vmod_curl_list_sz++) {
			vmod_curl_list[vmod_curl_list_sz] =
			    malloc(sizeof(struct vmod_curl));
			cm_init(vmod_curl_list[vmod_curl_list_sz]);
		}
		assert(vmod_curl_list_sz == ns);
		AN(vmod_curl_list);
	}
	cm = vmod_curl_list[ctx->req->sp->fd];
	if (cm->vxid != ctx->req->sp->vxid) {
		cm_clear(cm);
		cm->vxid = ctx->req->sp->vxid;
	}
	AZ(pthread_mutex_unlock(&cl_mtx));
	/*	Following sync block affects only this 'cm' instance.
		It's necessary because the request, which previously
		used this 'cm' (vmod_curl) instance could finish
		faster then the curl easy preparation
		in the 'no_wait' mode, and this 'cm' instance
		could be reused by current request while still
		not ready for that.
	*/
	AZ(pthread_mutex_lock(&cm->mtx));
	while (cm->performing) {
		AZ(pthread_cond_wait(&cm->cond, &cm->mtx));
	}
	if (reserve_for_call) {
		cm_clear_fetch_state(cm);
		cm->performing = 1;
	}
	AZ(pthread_mutex_unlock(&cm->mtx));
	return (cm);
}

static struct vmod_curl *
cm_get(const struct vrt_ctx *ctx) {
	return cm_get_reserve(ctx, 0);
}

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	int i;

	(void)priv;
	(void)conf;

	if (initialised)
		return (0);

	initialised = 1;

	vmod_curl_list = NULL;
	vmod_curl_list_sz = 256;
	vmod_curl_list = malloc(sizeof(struct vmod_curl *) * 256);
	AN(vmod_curl_list);
	for (i = 0; i < vmod_curl_list_sz; i++) {
		vmod_curl_list[i] = malloc(sizeof(struct vmod_curl));
		cm_init(vmod_curl_list[i]);
	}
	start_event_loop();
	return 0;
}

static size_t
recv_data(void *ptr, size_t size, size_t nmemb, void *s)
{
	struct vmod_curl *vc;

	CAST_OBJ_NOTNULL(vc, s, VMOD_CURL_MAGIC);

	VSB_bcat(vc->body, ptr, size * nmemb);
	return (size * nmemb);
}

static size_t
recv_hdrs(void *ptr, size_t size, size_t nmemb, void *s)
{
	struct vmod_curl *vc;
	struct hdr *h;
	char *split;
	ptrdiff_t keylen, vallen;

	CAST_OBJ_NOTNULL(vc, s, VMOD_CURL_MAGIC);

	split = memchr(ptr, ':', size * nmemb);
	if (split == NULL)
		return (size * nmemb);

	keylen = split - (char *)ptr;
	assert(keylen >= 0);
	if (keylen == 0)
		return (size * nmemb);

	h = calloc(1, sizeof(struct hdr));
	AN(h);
	h->key = strndup(ptr, keylen);
	AN(h->key);

	vallen = size * nmemb - keylen;
	assert(vallen > 0);	/* Counts ':' so always larger than 0 */
	split++;		/* Drop ':' */
	vallen--;
	while (vallen > 0 && isspace(*split)) {
		split++;
		vallen--;
	}
	while (vallen > 0 && isspace(*(split + vallen - 1)))
		vallen--;
	h->value = strndup(split, vallen);
	AN(h->value);

	VTAILQ_INSERT_HEAD(&vc->headers, h, list);

	return (size * nmemb);
}

static void
cm_perform(struct vmod_curl *c)
{
	CURL *curl_handle;
	CURLcode cr;
	struct curl_context *ctx;
	struct req_hdr *rh;

	ALLOC_OBJ(ctx, VMOD_CURL_CONTEXT_MAGIC);
	AN(ctx);

	curl_handle = curl_easy_init();
	AN(curl_handle);

	VTAILQ_FOREACH(rh, &c->req_headers, list)
		ctx->req_headers = curl_slist_append(ctx->req_headers, rh->value);

	if (c->flags & F_METHOD_POST) {
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
		if (c->no_wait)
			curl_easy_setopt(curl_handle, CURLOPT_COPYPOSTFIELDS,
				c->postfields);
		else
			curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS,
				c->postfields);
	} else if (c->flags & F_METHOD_HEAD)
		curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1L);
	else if (c->flags & F_METHOD_GET)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1L);

	if (ctx->req_headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, ctx->req_headers);

	curl_easy_setopt(curl_handle, CURLOPT_URL, c->url);
	curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

	if (!c->no_wait) {
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, recv_data);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, c);
		curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, recv_hdrs);
		curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, c);
		ctx->c = c;
	}
	curl_easy_setopt(curl_handle, CURLOPT_PRIVATE, ctx);

	if (c->proxy)
		curl_easy_setopt(curl_handle, CURLOPT_PROXY, c->proxy);

	if (c->timeout > 0) {
#ifdef CURL_TIMEOUTMS_WORKS
		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS,
		    c->timeout);
#else
		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT,
		    c->timeout / 1000);
#endif
	}

	if (c->connect_timeout > 0) {
#ifdef CURL_TIMEOUTMS_WORKS
		curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT_MS,
		    c->connect_timeout);
#else
		curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT,
		    c->connect_timeout / 1000);
#endif
	}

	if (c->flags & F_SSL_VERIFY_PEER)
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
	else
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);

	if (c->flags & F_SSL_VERIFY_HOST)
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 1L);
	else
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);

	if (c->cafile)
		curl_easy_setopt(curl_handle, CURLOPT_CAINFO, c->cafile);

	if (c->capath)
		curl_easy_setopt(curl_handle, CURLOPT_CAPATH, c->capath);

	curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, c->method);

	cm_clear_req_headers(c);

	if (c->no_wait) {
		VSB_finish(c->body);
		c->method = NULL;
		AZ(pthread_mutex_lock(&c->mtx));
		c->performing = 0;
		AZ(pthread_cond_signal(&c->cond));
		AZ(pthread_mutex_unlock(&c->mtx));
	}

	AZ(curl_multi_add_handle(multi_handle, curl_handle));
}

/*============= CURL MULTI ==============*/

/*creates the libuv socket context*/
static struct socket_context*
libuv_create_socket_context(curl_socket_t sockfd)
{
	struct socket_context *context;

	ALLOC_OBJ(context, VMOD_SOCKET_CONTEXT_MAGIC);
	CHECK_OBJ_NOTNULL(context, VMOD_SOCKET_CONTEXT_MAGIC);

	context->sockfd = sockfd;

	uv_poll_init_socket(loop, &context->poll_handle, sockfd);
	context->poll_handle.data = context;

	return context;
}

static void
libuv_socket_close_cb(uv_handle_t *handle)
{
	FREE_OBJ((struct socket_context*) handle->data);
}

static void
libuv_destroy_socket_context(struct socket_context* context)
{
	uv_close((uv_handle_t*) &context->poll_handle,
		libuv_socket_close_cb);
}

/*checks easy transfers states*/
static void
multi_check_easy_transfers(void)
{
	char *done_url;
	CURLMsg *message;
	int pending;
	struct curl_context *ctx;
	while ((message = curl_multi_info_read(multi_handle, &pending))) {
		switch (message->msg) {
			case CURLMSG_DONE:
				curl_easy_getinfo(message->easy_handle,
					CURLINFO_PRIVATE, &ctx);
				AN(ctx);
				if (ctx->c) {
					AZ(curl_easy_getinfo(message->easy_handle,
						CURLINFO_RESPONSE_CODE, &ctx->c->status));
					if (message->data.result != 0) {
						ctx->c->error = curl_easy_strerror(message->data.result);
						ctx->c->status = 0;
					}
					VSB_finish(ctx->c->body);
					ctx->c->method = NULL;
				}
				AZ(curl_multi_remove_handle(multi_handle, message->easy_handle));
				if (ctx->req_headers)
					curl_slist_free_all(ctx->req_headers);
				curl_easy_cleanup(message->easy_handle);
				if (ctx->c) {
					AZ(pthread_mutex_lock(&ctx->c->mtx));
					ctx->c->performing = 0;
					AZ(pthread_cond_signal(&ctx->c->cond));
					AZ(pthread_mutex_unlock(&ctx->c->mtx));
				}
				FREE_OBJ(ctx);
				break;
			default:
				break;
		}
	}
}

/*libuv socket event callback*/
static void
libuv_socket_cb(uv_poll_t *req, int status, int events)
{
	int running_handles;
	int flags = 0;
	struct socket_context *context;
	char *done_url;
	CURLMsg *message;
	int pending;

	uv_timer_stop(&timeout);

	if (events & UV_READABLE)
		flags |= CURL_CSELECT_IN;
	if (events & UV_WRITABLE)
		flags |= CURL_CSELECT_OUT;

	CAST_OBJ_NOTNULL(context, req->data, VMOD_SOCKET_CONTEXT_MAGIC);

	curl_multi_socket_action(multi_handle, context->sockfd, flags,
	                       &running_handles);

	multi_check_easy_transfers();
}

/*libuv timeout event callback*/
static void
libuv_timeout_cb(uv_timer_t *req, int status)
{
	int running_handles;
	curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0,
	                       &running_handles);
	multi_check_easy_transfers();
}

/*curl multi timeout event callback*/
static void
multi_timeout_cb(CURLM *multi, long timeout_ms, void *userp)
{
	if (timeout_ms <= 0)
		timeout_ms = 1;
	uv_timer_start(&timeout, (uv_timer_cb) libuv_timeout_cb, timeout_ms, 0);
}

/*curl multi socket callback*/
static int
multi_socket_cb(CURL *easy, curl_socket_t s, int action, void *userp,
                  void *socketp)
{
	struct socket_context *context;
	if (action == CURL_POLL_IN || action == CURL_POLL_OUT) {
		if (socketp)
			CAST_OBJ_NOTNULL(context, socketp, VMOD_SOCKET_CONTEXT_MAGIC);
		else
			context = libuv_create_socket_context(s);
		curl_multi_assign(multi_handle, s, (void *) context);
	}

	switch (action) {
		case CURL_POLL_IN:
			uv_poll_start(&context->poll_handle, UV_READABLE, libuv_socket_cb);
			break;
		case CURL_POLL_OUT:
			uv_poll_start(&context->poll_handle, UV_WRITABLE, libuv_socket_cb);
			break;
		case CURL_POLL_REMOVE:
			if (socketp) {
				CAST_OBJ_NOTNULL(context, socketp, VMOD_SOCKET_CONTEXT_MAGIC);
				uv_poll_stop(&context->poll_handle);
				libuv_destroy_socket_context(context);
				curl_multi_assign(multi_handle, s, NULL);
			}
			break;
		default:
			abort();
	}
	return 0;
}

/*the async event callback (triggered by a signal from the varnish request thread)*/
static void
libuv_async_cb(uv_async_t *handle, int status)
{
	struct vmod_curl *c;

	CAST_OBJ_NOTNULL(c, handle->data, VMOD_CURL_MAGIC);

	cm_perform(c);

	AZ(pthread_mutex_lock(&gl_mtx));
	callback_running = 0;
	AZ(pthread_cond_signal(&gl_cond));
	AZ(pthread_mutex_unlock(&gl_mtx));
}

/*the pthread worker running the libuv loop*/
static void*
multi_curl_worker(void* ptr)
{
	CURLcode code;

	loop = uv_default_loop();
	AN(loop);

	uv_timer_init(loop, &timeout);
	uv_async_init(loop, &async, (uv_async_cb)libuv_async_cb);

	AZ(curl_global_init(CURL_GLOBAL_ALL));

	multi_handle = curl_multi_init();
	AN(multi_handle);
	AZ(curl_multi_setopt(multi_handle, CURLMOPT_SOCKETFUNCTION, multi_socket_cb));
	AZ(curl_multi_setopt(multi_handle, CURLMOPT_TIMERFUNCTION, multi_timeout_cb));
	AZ(uv_run(loop, UV_RUN_DEFAULT));
}

/*starts the libuv event loop in a dedicated thread.*/
static void
start_event_loop(void)
{
	pthread_t loop_thread = NULL;
	int result = INT_MAX;
	AZ(pthread_create(&loop_thread, NULL, &multi_curl_worker, &result));
	AN(loop_thread);
}

/*signals the loop thread to perform a new curl call
*/
static void
cm_perform_async(struct vmod_curl *c)
{
	/* NOTE: uv_async_send call needs to be
	   synchronized, otherwise, especially in high load conditions
	   events can cumulate and the callback can be called
	   only once per such a cumulated group.
	   See: http://nikhilm.github.io/uvbook/threads.html#inter-thread-communication
	*/
	AZ(pthread_mutex_lock(&gl_mtx));
	while (callback_running) {
		AZ(pthread_cond_wait(&gl_cond, &gl_mtx));
	}
	callback_running = 1;
	async.data = c;
	uv_async_send(&async);
	AZ(pthread_mutex_unlock(&gl_mtx));
}

/*============= EOF CURL MULTI ==========*/

VCL_VOID
vmod_fetch(const struct vrt_ctx *ctx, VCL_STRING url)
{
	vmod_get(ctx, url);
}

VCL_VOID
vmod_get(const struct vrt_ctx *ctx, VCL_STRING url)
{
	struct vmod_curl *c;
	c = cm_get_reserve(ctx, 1);
	c->url = url;
	c->flags |= F_METHOD_GET;
	cm_perform_async(c);
}

VCL_VOID
vmod_head(const struct vrt_ctx *ctx, VCL_STRING url)
{
	struct vmod_curl *c;
	c = cm_get_reserve(ctx, 1);
	c->url = url;
	c->flags |= F_METHOD_HEAD;
	cm_perform_async(c);
}

VCL_VOID
vmod_post(const struct vrt_ctx *ctx, VCL_STRING url, VCL_STRING postfields)
{
	struct vmod_curl *c;
	c = cm_get_reserve(ctx, 1);
	c->url = url;
	c->flags |= F_METHOD_POST;
	c->postfields = postfields;
	cm_perform_async(c);
}

VCL_INT
vmod_status(const struct vrt_ctx *ctx)
{
	struct vmod_curl *c;
	c = cm_get(ctx);
	if (c->no_wait)
		return 0;
	return (c->status);
}

VCL_VOID
vmod_free(const struct vrt_ctx *ctx)
{
	struct vmod_curl *c;
	c = cm_get(ctx);
	cm_clear(c);
}

VCL_STRING
vmod_error(const struct vrt_ctx *ctx)
{
	struct vmod_curl *c;
	c = cm_get(ctx);
	if (c->status != 0 || c->no_wait)
		return (NULL);
	return (c->error);
}

VCL_STRING
vmod_header(const struct vrt_ctx *ctx, VCL_STRING header)
{
	struct hdr *h;
	const char *r = NULL;
	struct vmod_curl *c;

	c = cm_get(ctx);

	if (c->status == 0 || c->no_wait)
		return (NULL);

	VTAILQ_FOREACH(h, &c->headers, list) {
		if (strcasecmp(h->key, header) == 0) {
			r = h->value;
			break;
		}
	}
	return (r);
}

VCL_STRING
vmod_body(const struct vrt_ctx *ctx)
{
	struct vmod_curl *c;
	c = cm_get(ctx);
	if (c->status == 0 || c->no_wait)
		return (NULL);
	return (VSB_data(c->body));
}

VCL_VOID
vmod_set_timeout(const struct vrt_ctx *ctx, VCL_INT timeout)
{
	cm_get(ctx)->timeout = timeout;
}

VCL_VOID
vmod_set_connect_timeout(const struct vrt_ctx *ctx, VCL_INT timeout)
{
	cm_get(ctx)->connect_timeout = timeout;
}

VCL_VOID
vmod_set_ssl_verify_peer(const struct vrt_ctx *ctx, VCL_INT verify)
{
	if (verify)
		cm_get(ctx)->flags |= F_SSL_VERIFY_PEER;
	else
		cm_get(ctx)->flags &= ~F_SSL_VERIFY_PEER;
}

VCL_VOID
vmod_set_ssl_verify_host(const struct vrt_ctx *ctx, VCL_INT verify)
{
	if (verify)
		cm_get(ctx)->flags |= F_SSL_VERIFY_HOST;
	else
		cm_get(ctx)->flags &= ~F_SSL_VERIFY_HOST;
}

VCL_VOID
vmod_set_ssl_cafile(const struct vrt_ctx *ctx, VCL_STRING path)
{
	cm_get(ctx)->cafile = path;
}

VCL_VOID
vmod_set_ssl_capath(const struct vrt_ctx *ctx, VCL_STRING path)
{
	cm_get(ctx)->capath = path;
}

VCL_VOID
vmod_header_add(const struct vrt_ctx *ctx, VCL_STRING value)
{
	struct vmod_curl *c;
	struct req_hdr *rh;

	c = cm_get(ctx);

	rh = calloc(1, sizeof(struct req_hdr));
	AN(rh);
	rh->value = strdup(value);
	AN(rh->value);

	VTAILQ_INSERT_HEAD(&c->req_headers, rh, list);
}

VCL_VOID
vmod_header_remove(const struct vrt_ctx *ctx, VCL_STRING header)
{
	struct vmod_curl *c;
	struct req_hdr *rh;
	char *split, *s;

	c = cm_get(ctx);

	VTAILQ_FOREACH(rh, &c->req_headers, list) {
		s = strdup(rh->value);
		AN(s);
		if ((split = strchr(s, ':')) != NULL)
			*split = '\x0';
		if (strcasecmp(s, header) == 0) {
			VTAILQ_REMOVE(&c->req_headers, rh, list);
			free(rh->value);
			free(rh);
		}
		free(s);
	}
}

VCL_STRING
vmod_escape(const struct vrt_ctx *ctx, VCL_STRING str)
{
	CURL *curl_handle;
	char *esc, *r;

	curl_handle = curl_easy_init();
	AN(curl_handle);

	esc = curl_easy_escape(curl_handle, str, 0);
	AN(esc);
	r = WS_Copy(ctx->ws, esc, -1);
	curl_free(esc);
	curl_easy_cleanup(curl_handle);

	return (r);
}

VCL_STRING
vmod_unescape(const struct vrt_ctx *ctx, VCL_STRING str)
{
	CURL *curl_handle;
	char *tmp, *r;

	curl_handle = curl_easy_init();
	AN(curl_handle);

	tmp = curl_easy_unescape(curl_handle, str, 0, NULL);
	AN(tmp);
	r = WS_Copy(ctx->ws, tmp, -1);
	curl_free(tmp);
	curl_easy_cleanup(curl_handle);

	return (r);
}

VCL_VOID
vmod_proxy(const struct vrt_ctx *ctx, VCL_STRING proxy)
{
	vmod_set_proxy(ctx, proxy);
}

VCL_VOID
vmod_set_proxy(const struct vrt_ctx *ctx, VCL_STRING proxy)
{
	cm_get(ctx)->proxy = proxy;
}

VCL_VOID
vmod_set_method(const struct vrt_ctx *ctx, VCL_STRING name)
{
	cm_get(ctx)->method = name;
}

VCL_VOID
vmod_set_no_wait(const struct vrt_ctx *ctx, VCL_INT no_wait)
{
	cm_get(ctx)->no_wait = no_wait;
}
