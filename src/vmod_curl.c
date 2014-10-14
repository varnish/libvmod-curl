#include <stdlib.h>
#include <curl/curl.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include "vrt.h"
#include "vsb.h"
#include "cache/cache.h"

#include "vcc_if.h"
#include "config.h"

#define MAX_CURL_HANDLE_USAGE_COUNT	1000

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
	CURL *curl_handle;
	unsigned curl_handle_usage_count;
};

struct vmod_curl_priv {
	struct vmod_curl **vmod_curl_list;
	int vmod_curl_list_sz;
	pthread_mutex_t cl_mtx;
};

static int initialised = 0;
static int curl_handle_max_usage_count = MAX_CURL_HANDLE_USAGE_COUNT;

static void cm_clear(struct vmod_curl *c);

static void
cm_init(struct vmod_curl *c)
{
	c->magic = VMOD_CURL_MAGIC;
	VTAILQ_INIT(&c->headers);
	VTAILQ_INIT(&c->req_headers);
	c->body = VSB_new_auto();
	c->curl_handle = NULL;
	c->curl_handle_usage_count = 0;
	cm_clear(c);
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
	
	if (c->curl_handle_usage_count > curl_handle_max_usage_count) {
		curl_easy_cleanup(c->curl_handle);
		c->curl_handle_usage_count = 0;
		c->curl_handle = NULL;
	}
	
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
}

static struct vmod_curl *
cm_get(const struct vrt_ctx *ctx, struct vmod_curl_priv *cm_priv)
{
	struct vmod_curl *cm;

	AZ(pthread_mutex_lock(&cm_priv->cl_mtx));

	while (cm_priv->vmod_curl_list_sz <= ctx->req->sp->fd) {
		int ns = cm_priv->vmod_curl_list_sz * 2;
		/* resize array */
		cm_priv->vmod_curl_list =
		    realloc(cm_priv->vmod_curl_list, ns * sizeof(struct vmod_curl *));
		for (; cm_priv->vmod_curl_list_sz < ns; cm_priv->vmod_curl_list_sz++) {
			cm_priv->vmod_curl_list[cm_priv->vmod_curl_list_sz] =
			    malloc(sizeof(struct vmod_curl));
			cm_init(cm_priv->vmod_curl_list[cm_priv->vmod_curl_list_sz]);
		}
		assert(cm_priv->vmod_curl_list_sz == ns);
		AN(cm_priv->vmod_curl_list);
	}
	cm = cm_priv->vmod_curl_list[ctx->req->sp->fd];
	if (cm->vxid != ctx->req->sp->vxid) {
		cm_clear(cm);
		cm->vxid = ctx->req->sp->vxid;
	}
	AZ(pthread_mutex_unlock(&cm_priv->cl_mtx));
	return (cm);
}

static void fini_function(void *);

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	int i;

	(void)priv;
	(void)conf;
	
	struct vmod_curl_priv *cm_priv = malloc(sizeof(struct vmod_curl_priv));
	AN(cm_priv);
	priv->priv = cm_priv;
	priv->free = fini_function;

	cm_priv->vmod_curl_list = NULL;
	cm_priv->vmod_curl_list_sz = 256;
	cm_priv->vmod_curl_list = malloc(sizeof(struct vmod_curl *) * 256);
	AN(cm_priv->vmod_curl_list);
	for (i = 0; i < cm_priv->vmod_curl_list_sz; i++) {
		cm_priv->vmod_curl_list[i] = malloc(sizeof(struct vmod_curl));
		cm_init(cm_priv->vmod_curl_list[i]);
	}
	AZ(pthread_mutex_init(&cm_priv->cl_mtx, NULL));
	
	initialised++;

	if (initialised > 1)
		return (0);

	return (curl_global_init(CURL_GLOBAL_ALL));
}

static void
fini_function(void *priv_data)
{
	struct vmod_curl_priv *cm_priv = (struct vmod_curl_priv *)priv_data;
	int i;
	
	AZ(pthread_mutex_destroy(&cm_priv->cl_mtx));
	for (i = 0; i < cm_priv->vmod_curl_list_sz; i++) {
		struct vmod_curl *cm = cm_priv->vmod_curl_list[i];
		if (cm->curl_handle != NULL) {
			curl_easy_cleanup(cm->curl_handle);
		}
		free(cm);
	}
	free(cm_priv->vmod_curl_list);
	free(cm_priv);
	
	initialised--;
	
	if (initialised == 0) {
		curl_global_cleanup();
	}
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
	struct curl_slist *req_headers = NULL;
	struct req_hdr *rh;

	if (c->curl_handle != NULL) {
		c->curl_handle_usage_count++;
		curl_easy_reset(c->curl_handle);
	}
	else {
		c->curl_handle = curl_easy_init();
		c->curl_handle_usage_count = 1;
	}
	curl_handle = c->curl_handle;
	AN(curl_handle);

	VTAILQ_FOREACH(rh, &c->req_headers, list)
		req_headers = curl_slist_append(req_headers, rh->value);

	if (c->flags & F_METHOD_POST) {
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS,
		    c->postfields);
	} else if (c->flags & F_METHOD_HEAD)
		curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1L);
	else if (c->flags & F_METHOD_GET)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1L);

	if (req_headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, req_headers);

	curl_easy_setopt(curl_handle, CURLOPT_URL, c->url);
	curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, recv_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, c);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, recv_hdrs);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, c);

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

	cr = curl_easy_perform(curl_handle);

	if (cr != 0) {
		c->error = curl_easy_strerror(cr);
		curl_easy_cleanup(curl_handle);
		c->curl_handle = NULL;
	}
	else {
		curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &c->status);
	}

	if (req_headers)
		curl_slist_free_all(req_headers);

	c->method = NULL;

	cm_clear_req_headers(c);
	VSB_finish(c->body);
}

VCL_VOID
vmod_fetch(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING url)
{
	vmod_get(ctx, priv, url);
}

VCL_VOID
vmod_get(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING url)
{
	struct vmod_curl *c;
	c = cm_get(ctx, (struct vmod_curl_priv *)priv->priv);
	cm_clear_fetch_state(c);
	c->url = url;
	c->flags |= F_METHOD_GET;
	cm_perform(c);
}

VCL_VOID
vmod_head(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING url)
{
	struct vmod_curl *c;
	c = cm_get(ctx, (struct vmod_curl_priv *)priv->priv);
	cm_clear_fetch_state(c);
	c->url = url;
	c->flags |= F_METHOD_HEAD;
	cm_perform(c);
}

VCL_VOID
vmod_post(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING url, VCL_STRING postfields)
{
	struct vmod_curl *c;
	c = cm_get(ctx, (struct vmod_curl_priv *)priv->priv);
	cm_clear_fetch_state(c);
	c->url = url;
	c->flags |= F_METHOD_POST;
	c->postfields = postfields;
	cm_perform(c);
}

VCL_INT
vmod_status(const struct vrt_ctx *ctx, struct vmod_priv *priv)
{
	return (cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->status);
}

VCL_VOID
vmod_free(const struct vrt_ctx *ctx, struct vmod_priv *priv)
{
	cm_clear(cm_get(ctx, (struct vmod_curl_priv *)priv->priv));
}

VCL_STRING
vmod_error(const struct vrt_ctx *ctx, struct vmod_priv *priv)
{
	struct vmod_curl *c;

	c = cm_get(ctx, (struct vmod_curl_priv *)priv->priv);
	if (c->status != 0)
		return (NULL);
	return (c->error);
}

VCL_STRING
vmod_header(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING header)
{
	struct hdr *h;
	const char *r = NULL;
	struct vmod_curl *c;

	c = cm_get(ctx, (struct vmod_curl_priv *)priv->priv);

	VTAILQ_FOREACH(h, &c->headers, list) {
		if (strcasecmp(h->key, header) == 0) {
			r = h->value;
			break;
		}
	}
	return (r);
}

VCL_STRING
vmod_body(const struct vrt_ctx *ctx, struct vmod_priv *priv)
{
	return (VSB_data(cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->body));
}

VCL_VOID
vmod_set_timeout(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_INT timeout)
{
	cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->timeout = timeout;
}

VCL_VOID
vmod_set_connect_timeout(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_INT timeout)
{
	cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->connect_timeout = timeout;
}

VCL_VOID
vmod_set_ssl_verify_peer(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_INT verify)
{
	if (verify)
		cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->flags |= F_SSL_VERIFY_PEER;
	else
		cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->flags &= ~F_SSL_VERIFY_PEER;
}

VCL_VOID
vmod_set_ssl_verify_host(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_INT verify)
{
	if (verify)
		cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->flags |= F_SSL_VERIFY_HOST;
	else
		cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->flags &= ~F_SSL_VERIFY_HOST;
}

VCL_VOID
vmod_set_ssl_cafile(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING path)
{
	cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->cafile = path;
}

VCL_VOID
vmod_set_ssl_capath(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING path)
{
	cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->capath = path;
}

VCL_VOID
vmod_header_add(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING value)
{
	struct vmod_curl *c;
	struct req_hdr *rh;

	c = cm_get(ctx, (struct vmod_curl_priv *)priv->priv);

	rh = calloc(1, sizeof(struct req_hdr));
	AN(rh);
	rh->value = strdup(value);
	AN(rh->value);

	VTAILQ_INSERT_HEAD(&c->req_headers, rh, list);
}

VCL_VOID
vmod_header_remove(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING header)
{
	struct vmod_curl *c;
	struct req_hdr *rh;
	char *split, *s;

	c = cm_get(ctx, (struct vmod_curl_priv *)priv->priv);

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
vmod_escape(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING str)
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
vmod_unescape(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING str)
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
vmod_proxy(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING proxy)
{
	vmod_set_proxy(ctx, priv, proxy);
}

VCL_VOID
vmod_set_proxy(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING proxy)
{
	cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->proxy = proxy;
}

VCL_VOID
vmod_set_method(const struct vrt_ctx *ctx, struct vmod_priv *priv, VCL_STRING name)
{
	cm_get(ctx, (struct vmod_curl_priv *)priv->priv)->method = name;
}

VCL_VOID
vmod_set_curl_handle_max_usage_count(const struct vrt_ctx *ctx, VCL_INT count)
{
	if (count > 0) {
		curl_handle_max_usage_count = count;
	}
}
