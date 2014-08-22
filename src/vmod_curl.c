#include <stdlib.h>
#include <curl/curl.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>

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


#define VMOD_CURL_LIST_SZ_INC 215

struct vmod_curl {
	unsigned	magic;
#define VMOD_CURL_MAGIC 0xBBB0C87C
	unsigned vxid;
	int 		async;
	long		status;
	long		timeout_ms;
	long		connect_timeout_ms;
	char		flags;
#define VC_VERIFY_PEER (1 << 0)
#define VC_VERIFY_HOST (1 << 1)
	const char	*url;
	const char	*method;
	const char	*postfields;
	const char	*error;
	const char	*cafile;
	const char	*capath;
	VTAILQ_HEAD(, hdr) headers;
	VTAILQ_HEAD(, req_hdr) req_headers;
	const char 	*proxy;
	struct vsb	*body;
	struct ws *ws; 
};

static int initialised = 0;

static struct vmod_curl **vmod_curl_list;
int vmod_curl_list_sz;
static pthread_mutex_t cl_mtx = PTHREAD_MUTEX_INITIALIZER;
static void cm_clear(struct vmod_curl *c);

static void cm_init(struct vmod_curl *c) {
	c->magic = VMOD_CURL_MAGIC;
	VTAILQ_INIT(&c->headers);
	VTAILQ_INIT(&c->req_headers);
	c->body = VSB_new_auto();
	cm_clear(c);
}

static void cm_clear_body(struct vmod_curl *c) {

	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	VSB_clear(c->body);
}

static void cm_clear_headers(struct vmod_curl *c) {
	struct hdr *h, *h2;

	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	VTAILQ_FOREACH_SAFE(h, &c->headers, list, h2) {
		VTAILQ_REMOVE(&c->headers, h, list);
		free(h->key);
		free(h->value);
		free(h);
	}
}

static void cm_clear_req_headers(struct vmod_curl *c) {
	struct req_hdr *rh, *rh2;

	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	VTAILQ_FOREACH_SAFE(rh, &c->req_headers, list, rh2) {
		VTAILQ_REMOVE(&c->req_headers, rh, list);
		free(rh->value);
		free(rh);
	}
}

static void cm_clear_fetch_state(struct vmod_curl *c) {
	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	c->method = NULL;
	cm_clear_body(c);
	cm_clear_headers(c);
}

static void cm_clear(struct vmod_curl *c) {
	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);
	cm_clear_fetch_state(c);
	c->async = 0;
	c->status = 0;
	c->timeout_ms = -1;
	c->connect_timeout_ms = -1;
	c->flags = 0;
	c->cafile = NULL;
	c->capath = NULL;
	c->error = NULL;
	c->vxid = 0;
	c->proxy = NULL;
	c->ws = NULL;
}

static struct vmod_curl* cm_get(const struct vrt_ctx *ctx) {
	struct vmod_curl *cm;
	AZ(pthread_mutex_lock(&cl_mtx));

	while (vmod_curl_list_sz <= ctx->req->sp->fd) {
		int ns = vmod_curl_list_sz + VMOD_CURL_LIST_SZ_INC;
		/* resize array */
		vmod_curl_list = realloc(vmod_curl_list, ns * sizeof(struct vmod_curl *));
		for (; vmod_curl_list_sz < ns; vmod_curl_list_sz++) {
			vmod_curl_list[vmod_curl_list_sz] = malloc(sizeof(struct vmod_curl));
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
	cm->ws = ctx->ws;
	AZ(pthread_mutex_unlock(&cl_mtx));
	return cm;
}

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	int i;

	(void)priv;
	(void)conf;

	if (initialised)
	  return 0;

	initialised = 1;

	vmod_curl_list = NULL;
	vmod_curl_list_sz = VMOD_CURL_LIST_SZ_INC;
	vmod_curl_list = malloc(sizeof(struct vmod_curl *) * VMOD_CURL_LIST_SZ_INC);
	AN(vmod_curl_list);
	for (i = 0 ; i < vmod_curl_list_sz; i++) {
		vmod_curl_list[i] = malloc(sizeof(struct vmod_curl));
		cm_init(vmod_curl_list[i]);
	}
	return (curl_global_init(CURL_GLOBAL_ALL));
}

static size_t recv_data(void *ptr, size_t size, size_t nmemb, void *s)
{
	struct vmod_curl *vc;

	CAST_OBJ_NOTNULL(vc, s, VMOD_CURL_MAGIC);
	// we don't care about the result in async calls
	if (!vc->async) {
	    VSB_bcat(vc->body, ptr, size * nmemb);
	}
	return size * nmemb;
}

static size_t recv_hdrs(void *ptr, size_t size, size_t nmemb, void *s)
{
	struct vmod_curl *vc;
	struct hdr *h;
	char *split;
	ptrdiff_t keylen, vallen;

	CAST_OBJ_NOTNULL(vc, s, VMOD_CURL_MAGIC);

	// we don't care about the result in async calls
	if (vc->async) {
	    return (size * nmemb);
	}


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

	vallen = size*nmemb - keylen;
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

// free the vmod_curl structure mem allocation (dedicated for async calls)
static void cm_free(void *arg) {
    struct vmod_curl *c;
    CAST_OBJ_NOTNULL(c, arg, VMOD_CURL_MAGIC);
    if (c->async) {
	//clear workspace allocation
	if (c->ws && c->ws->s) {
	    free(c->ws->s);
	}
	c->ws = NULL;
    }
}

// actual cUrl request, called either directly or as a pthread worker method
static void* cm_perform_sync(struct vmod_curl *c) {
	CURL *curl_handle;
	CURLcode cr;
	struct curl_slist *req_headers = NULL;
	struct req_hdr *rh;
	
	// thread cleanup handler
	pthread_cleanup_push(cm_free, (void*) c);
	
	curl_handle = curl_easy_init();
	AN(curl_handle);

	VTAILQ_FOREACH(rh, &c->req_headers, list) {
		req_headers = curl_slist_append(req_headers, rh->value);
	}

	if (c->method && strcmp(c->method, "POST") == 0) {
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, c->postfields);

	}
	if (c->method && strcmp(c->method, "HEAD") == 0) {
		curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1L);

	}
	if (req_headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, req_headers);
	curl_easy_setopt(curl_handle, CURLOPT_URL, c->url);
	curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL , 1L);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, recv_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, c);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, recv_hdrs);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, c);
	if(c->proxy) {
		curl_easy_setopt(curl_handle, CURLOPT_PROXY, c->proxy);
	}
	if (c->timeout_ms > 0) {
#ifdef CURL_TIMEOUTMS_WORKS
		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, c->timeout_ms);
#else
		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, c->timeout_ms / 1000);
#endif
	}

	if (c->connect_timeout_ms > 0) {
#ifdef CURL_TIMEOUTMS_WORKS
		curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT_MS, c->connect_timeout_ms);
#else
		curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, c->connect_timeout_ms / 1000);
#endif
	}

	if (c->flags & VC_VERIFY_PEER) {
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
	} else {
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	}

	if (c->flags & VC_VERIFY_HOST) {
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 1L);
	} else {
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	if (c->cafile) {
		      curl_easy_setopt(curl_handle, CURLOPT_CAINFO, c->cafile);
	}

	if (c->capath) {
		      curl_easy_setopt(curl_handle, CURLOPT_CAPATH, c->capath);
	}

	cr = curl_easy_perform(curl_handle);

	if (cr != 0) {
		c->error = curl_easy_strerror(cr);
	} else {
	    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &c->status);
	}


	if (req_headers)
		curl_slist_free_all(req_headers);
	if (!c->async) {
	    cm_clear_req_headers(c);
	}
	curl_easy_cleanup(curl_handle);
	VSB_finish(c->body);
        // call cleanup handler 
	pthread_cleanup_pop(1);
}

// deep clone of the vmod_curl structure instance for the async call
static struct vmod_curl* cm_clone(struct vmod_curl *src, struct ws *aws) {
	struct vmod_curl* target;
	struct req_hdr *rh;
	struct req_hdr *rh_clone;
	
	target = WS_Alloc(aws, sizeof(struct vmod_curl));
	if (target == NULL) {
	    return NULL;
	}
	cm_init(target);
	
	target->ws = WS_Alloc(aws, sizeof(struct ws));
	if (target->ws == NULL) {
	    return NULL;
	}	
	memcpy(target->ws, aws, sizeof(struct ws));

	target->async = src->async;
	target->timeout_ms = src->timeout_ms;
	target->connect_timeout_ms = src->connect_timeout_ms;
	target->flags = src->flags;
	target->vxid = src->vxid;

	target->url = WS_Copy(target->ws, src->url, strlen(src->url) + 1);
	if (target->url == NULL) {
	    cm_free(target);
	    return NULL;
	}

	target->method = WS_Copy(target->ws, src->method, strlen(src->method) + 1);
	if (target->method == NULL) {
	    cm_free(target);
	    return NULL;
	}

	if (src->postfields) {
	    target->postfields = WS_Copy(target->ws, src->postfields, strlen(src->postfields) + 1);
	    if (target->postfields == NULL) {
		cm_free(target);
		return NULL;
	    }	   
	}
	if (src->cafile) {
	    target->cafile = WS_Copy(target->ws, src->cafile, strlen(src->cafile) + 1);
	    if (target->cafile == NULL) {
		cm_free(target);
		return NULL;
	    }	   
	}
	if (src->capath) {
	    target->capath = WS_Copy(target->ws, src->capath, strlen(src->capath) + 1);
	    if (target->capath == NULL) {
		cm_free(target);
		return NULL;
	    }	   
	}
	if (src->proxy) {
	    target->proxy = WS_Copy(target->ws, src->proxy, strlen(src->proxy) + 1);
	    if (target->proxy == NULL) {
		cm_free(target);
		return NULL;
	    }	   
	}
	if (VSB_len(src->body) > 0) {
	    VSB_cpy(target->body, VSB_data(src->body));
	}
	if (!VTAILQ_EMPTY(&src->req_headers)) {
	    VTAILQ_FOREACH(rh, &src->req_headers, list) {
		AN(rh);
		AN(rh->value);
	    	rh_clone = (struct req_hdr*) WS_Alloc(target->ws, sizeof(struct req_hdr));
		if (rh_clone == NULL) {
		    cm_free(target);
		    return NULL;
		}
		rh_clone->value = WS_Copy(target->ws, rh->value, strlen(rh->value) + 1);
		if (rh_clone->value == NULL) {
		    cm_free(target);
		    return NULL;
		}	   
		VTAILQ_INSERT_HEAD(&target->req_headers, rh_clone, list);
	    }
	}
	return target;
}

// the async call worker
static void* cm_worker(struct worker* wrk, void *priv) {
	struct vmod_curl *c;
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	AN(priv);
	CAST_OBJ_NOTNULL(c, priv, VMOD_CURL_MAGIC);
	AN(c);
        cm_perform_sync(c);
        cm_clear(c);
	pthread_exit(0);
}

// counts the allocated size (incl. the member pointers allocation)
static unsigned cm_size(struct vmod_curl *c) {
	unsigned result;
	struct req_hdr *rh;

	result = sizeof(struct vmod_curl);
	if (c->url) {
	    result += strlen(c->url) + 1;
	}
	if (c->method) {
	    result += strlen(c->method) + 1;
	}
	if (c->postfields) {
	    result += strlen(c->postfields) + 1;
	}
	if (c->cafile) {
	    result += strlen(c->cafile) + 1;
	}
	if (c->capath) {
	    result += strlen(c->capath) + 1;
	}
	if (c->proxy) {
	    result += strlen(c->proxy) + 1;
	}
	
	result += sizeof(struct vsb);
	if (c->body) {
	    result += VSB_len(c->body) + 1;
	}
	if (!VTAILQ_EMPTY(&c->req_headers)) {
	    VTAILQ_FOREACH(rh, &c->req_headers, list) {
		if (rh) {
		    result += sizeof(struct req_hdr);
		    if (rh->value) {
			result += strlen(rh->value) + 1;
		    }
		}
	    }
	}		
	result += sizeof(struct ws);
	return (1 + result/64) * 64;
}

static void cm_perform(struct vmod_curl *c) {
	pthread_t thread0;
	struct vmod_curl *c1;
	struct ws aws;
	unsigned alloc_size;
	if (c->async) {
		alloc_size = cm_size(c);
		aws.s = malloc(alloc_size);
		if (aws.s) {
		    WS_Init(&aws, "bth", aws.s, alloc_size);
		    c1 = cm_clone(c, &aws);
		    if (c1) {
			WRK_BgThread(&thread0, "async_thread", cm_worker, c1);
			if (&thread0) {
			    pthread_detach(thread0);
			    cm_clear_req_headers(c);
			    return;
			}
			// thread didn't start, so clean up the clone
			cm_free(c1);
		    } else {
			// clone hasn't been created so cleanup workspace mem directly
			free(aws.s);
		    }
		}
	} 
	c->async = 0;
	cm_perform_sync(c);
}

VCL_VOID
vmod_fetch(const struct vrt_ctx *ctx, VCL_STRING url)
{
	vmod_get(ctx, url);
}

VCL_VOID
vmod_get(const struct vrt_ctx *ctx, VCL_STRING url)
{
	struct vmod_curl *c;
	c = cm_get(ctx);
	cm_clear_fetch_state(c);
	c->url = url;
	c->method = "GET";
	cm_perform(c);
}

VCL_VOID
vmod_head(const struct vrt_ctx *ctx, VCL_STRING url)
{
	struct vmod_curl *c;
	c = cm_get(ctx);
	cm_clear_fetch_state(c);
	c->url = url;
	c->method = "HEAD";
	cm_perform(c);
}

VCL_VOID
vmod_post(const struct vrt_ctx *ctx, VCL_STRING url, VCL_STRING postfields)
{
	struct vmod_curl *c;
	c = cm_get(ctx);
	cm_clear_fetch_state(c);
	c->url = url;
	c->method = "POST";
	c->postfields = postfields;
	cm_perform(c);
}

VCL_INT
vmod_status(const struct vrt_ctx *ctx)
{
	int r;
	r = cm_get(ctx)->status;
	return r;
}

VCL_VOID
vmod_free(const struct vrt_ctx *ctx)
{
	cm_clear(cm_get(ctx));
}

VCL_STRING
vmod_error(const struct vrt_ctx *ctx)
{
	struct vmod_curl *c;

	c = cm_get(ctx);
	if (c->status != 0)
		return(NULL);
	return(c->error);
}

VCL_STRING
vmod_header(const struct vrt_ctx *ctx, VCL_STRING header)
{
	struct hdr *h;
	const char *r = NULL;
	struct vmod_curl *c;

	c = cm_get(ctx);

	VTAILQ_FOREACH(h, &c->headers, list) {
		if (strcasecmp(h->key, header) == 0) {
			r = h->value;
			break;
		}
	}
	return r;
}

VCL_STRING
vmod_body(const struct vrt_ctx *ctx)
{
	return VSB_data(cm_get(ctx)->body);
}

VCL_VOID
vmod_set_timeout(const struct vrt_ctx *ctx, VCL_INT timeout)
{
	cm_get(ctx)->timeout_ms = timeout;
}

VCL_VOID
vmod_set_connect_timeout(const struct vrt_ctx *ctx, VCL_INT timeout)
{
	cm_get(ctx)->connect_timeout_ms = timeout;
}

VCL_VOID
vmod_set_async(const struct vrt_ctx *ctx, VCL_INT async_flag)
{
	cm_get(ctx)->async = async_flag;
}

VCL_VOID
vmod_set_ssl_verify_peer(const struct vrt_ctx *ctx, VCL_INT verify)
{
	if (verify) {
		cm_get(ctx)->flags |= VC_VERIFY_PEER;
	} else {
		cm_get(ctx)->flags &= ~VC_VERIFY_PEER;
	}
}

VCL_VOID
vmod_set_ssl_verify_host(const struct vrt_ctx *ctx, VCL_INT verify)
{
	if (verify) {
		cm_get(ctx)->flags |= VC_VERIFY_HOST;
	} else {
		cm_get(ctx)->flags &= ~VC_VERIFY_HOST;
	}
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
	char *esc, *r;

	CURL *curl_handle;

	curl_handle = curl_easy_init();
	AN(curl_handle);

	esc = curl_easy_escape(curl_handle, str, 0);
	AN(esc);
	r = WS_Copy(ctx->ws, esc, -1);
	curl_free(esc);
	curl_easy_cleanup(curl_handle);

	return r;
}

VCL_STRING
vmod_unescape(const struct vrt_ctx *ctx, VCL_STRING str)
{
	char *tmp, *r;

	CURL *curl_handle;

	curl_handle = curl_easy_init();
	AN(curl_handle);

	tmp = curl_easy_unescape(curl_handle, str, 0, NULL);
	AN(tmp);
	r = WS_Copy(ctx->ws, tmp, -1);
	curl_free(tmp);
	curl_easy_cleanup(curl_handle);

	return r;
}

VCL_VOID
vmod_proxy(const struct vrt_ctx *ctx, VCL_STRING proxy) {
	cm_get(ctx)->proxy = proxy;
}


