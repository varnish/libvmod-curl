#include <stdlib.h>
#include <curl/curl.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include <cache/cache.h>

#ifndef VRT_H_INCLUDED
#  include <vrt.h>
#endif

#ifndef VDEF_H_INCLUDED
#  include <vdef.h>
#endif

#include <vcl.h>

#include "vsb.h"
#include "vcc_if.h"
#include "config.h"

#ifndef VRT_CTX
#define VRT_CTX		const struct vrt_ctx *ctx
#endif

struct hdr {
	char *key;
	char *value;
	VTAILQ_ENTRY(hdr) list;
};

struct req_hdr {
	char *value;
	VTAILQ_ENTRY(req_hdr) list;
};

enum debug_flags {
#define DBG(u,l,v)		DBG_##u = v,
#include "debug_flags.h"
#undef DBG
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
#ifdef HAVE_CURLOPT_UNIX_SOCKET_PATH
	const char *sun_path;
#endif
	VTAILQ_HEAD(, hdr) headers;
	VTAILQ_HEAD(, req_hdr) req_headers;
	const char *proxy;
	struct vsb *body;
	const struct vrt_ctx *vctx;
	unsigned debug_flags;
};

static void cm_clear(struct vmod_curl *c);

int
event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	(void)ctx;
	(void)priv;
	if (e != VCL_EVENT_LOAD)
		return (0);
	curl_global_init(CURL_GLOBAL_ALL);
	return (0);
}

static void
cm_init(struct vmod_curl *c)
{
	c->magic = VMOD_CURL_MAGIC;
	VTAILQ_INIT(&c->headers);
	VTAILQ_INIT(&c->req_headers);
	c->body = VSB_new_auto();
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

	c->connect_timeout = -1;
	c->timeout = -1;
	c->cafile = NULL;
	c->capath = NULL;
#ifdef HAVE_CURLOPT_UNIX_SOCKET_PATH
	c->sun_path = NULL;
#endif
	c->error = NULL;
	c->flags = 0;
	c->method = NULL;
	c->proxy = NULL;
	c->status = 0;
	c->vxid = 0;
	c->vctx = NULL;
	c->debug_flags = 0;
}

static int
cm_debug(CURL *handle, curl_infotype type, char *data, size_t size,
    void *userdata)
{
	struct vmod_curl *c;

	(void)handle;

	CAST_OBJ_NOTNULL(c, userdata, VMOD_CURL_MAGIC);
	CHECK_OBJ_NOTNULL(c->vctx, VRT_CTX_MAGIC);
	AN(c->debug_flags);
#define DBG(u,l,v) 							\
	if ((unsigned)type == CURLINFO_##u &&				\
	    (c->debug_flags & v) != 0)					\
		VSLb(c->vctx->vsl, SLT_Debug, #l ": %.*s",		\
		    (int)size, data);
#include "debug_flags.h"
#undef DBG
	return (0);
}

void
free_func(void *p)
{
	struct vmod_curl *c;

	CAST_OBJ_NOTNULL(c, p, VMOD_CURL_MAGIC);

	cm_clear_req_headers(c);
	cm_clear(c);
	VSB_delete(c->body);

	FREE_OBJ(c);
}

static struct vmod_curl *
cm_get(struct vmod_priv *priv)
{
	struct vmod_curl *cm;

	if (priv->priv == NULL) {
		ALLOC_OBJ(cm, VMOD_CURL_MAGIC);
		cm_init(cm);
		priv->priv = cm;
		priv->free = free_func;
	} else
		CAST_OBJ_NOTNULL(cm, priv->priv, VMOD_CURL_MAGIC);

	return (cm);
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

	curl_handle = curl_easy_init();
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
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER,
		    req_headers);

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
#ifdef HAVE_CURLOPT_TIMEOUT_MS
		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS,
		    c->timeout);
#else
		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT,
		    c->timeout / 1000);
#endif
	}

	if (c->connect_timeout > 0) {
#ifdef HAVE_CURLOPT_CONNECTTIMEOUT_MS
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

#ifdef HAVE_CURLOPT_UNIX_SOCKET_PATH
	if (c->sun_path)
		curl_easy_setopt(curl_handle, CURLOPT_UNIX_SOCKET_PATH,
		    c->sun_path);
#endif

	if (c->debug_flags != 0) {
		curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION,
		    cm_debug);
		curl_easy_setopt(curl_handle, CURLOPT_DEBUGDATA, c);
		curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
	} else
		curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);

	curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, c->method);

	cr = curl_easy_perform(curl_handle);

	if (cr != 0)
		c->error = curl_easy_strerror(cr);

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &c->status);

	if (req_headers)
		curl_slist_free_all(req_headers);

	c->method = NULL;

	cm_clear_req_headers(c);
	curl_easy_cleanup(curl_handle);
	VSB_finish(c->body);
}

VCL_VOID
vmod_fetch(VRT_CTX, struct vmod_priv *priv, VCL_STRING url)
{
	vmod_get(ctx, priv, url);
}

VCL_VOID
vmod_get(VRT_CTX, struct vmod_priv *priv, VCL_STRING url)
{
	struct vmod_curl *c;

	(void)ctx;

	c = cm_get(priv);
	cm_clear_fetch_state(c);
	c->url = url;
	c->flags |= F_METHOD_GET;
	cm_perform(c);
}

VCL_VOID
vmod_head(VRT_CTX, struct vmod_priv *priv, VCL_STRING url)
{
	struct vmod_curl *c;

	(void)ctx;

	c = cm_get(priv);
	cm_clear_fetch_state(c);
	c->url = url;
	c->flags |= F_METHOD_HEAD;
	cm_perform(c);
}

VCL_VOID
vmod_post(VRT_CTX, struct vmod_priv *priv, VCL_STRING url,
    VCL_STRING postfields)
{
	struct vmod_curl *c;

	(void)ctx;

	c = cm_get(priv);
	cm_clear_fetch_state(c);
	c->url = url;
	c->flags |= F_METHOD_POST;
	c->postfields = postfields;
	cm_perform(c);
}

VCL_INT
vmod_status(VRT_CTX, struct vmod_priv *priv)
{
	(void)ctx;
	return (cm_get(priv)->status);
}

VCL_VOID
vmod_free(VRT_CTX, struct vmod_priv *priv)
{
	(void)ctx;
	cm_clear(cm_get(priv));
}

VCL_STRING
vmod_error(VRT_CTX, struct vmod_priv *priv)
{
	struct vmod_curl *c;

	(void)ctx;

	c = cm_get(priv);
	if (c->status != 0)
		return (NULL);
	return (c->error);
}

VCL_STRING
vmod_header(VRT_CTX, struct vmod_priv *priv, VCL_STRING header)
{
	struct hdr *h;
	const char *r = NULL;
	struct vmod_curl *c;

	(void)ctx;

	c = cm_get(priv);

	VTAILQ_FOREACH(h, &c->headers, list) {
		if (strcasecmp(h->key, header) == 0) {
			r = h->value;
			break;
		}
	}
	return (r);
}

VCL_STRING
vmod_body(VRT_CTX, struct vmod_priv *priv)
{
	(void)ctx;
	return (VSB_data(cm_get(priv)->body));
}

VCL_VOID
vmod_set_timeout(VRT_CTX, struct vmod_priv *priv, VCL_INT timeout)
{
	(void)ctx;
	cm_get(priv)->timeout = timeout;
}

VCL_VOID
vmod_set_connect_timeout(VRT_CTX, struct vmod_priv *priv, VCL_INT timeout)
{
	(void)ctx;
	cm_get(priv)->connect_timeout = timeout;
}

VCL_VOID
vmod_set_ssl_verify_peer(VRT_CTX, struct vmod_priv *priv, VCL_INT verify)
{
	(void)ctx;

	if (verify)
		cm_get(priv)->flags |= F_SSL_VERIFY_PEER;
	else
		cm_get(priv)->flags &= ~F_SSL_VERIFY_PEER;
}

VCL_VOID
vmod_set_ssl_verify_host(VRT_CTX, struct vmod_priv *priv, VCL_INT verify)
{
	(void)ctx;

	if (verify)
		cm_get(priv)->flags |= F_SSL_VERIFY_HOST;
	else
		cm_get(priv)->flags &= ~F_SSL_VERIFY_HOST;
}

VCL_VOID
vmod_set_ssl_cafile(VRT_CTX, struct vmod_priv *priv, VCL_STRING path)
{
	(void)ctx;
	cm_get(priv)->cafile = path;
}

VCL_VOID
vmod_set_ssl_capath(VRT_CTX, struct vmod_priv *priv, VCL_STRING path)
{
	(void)ctx;
	cm_get(priv)->capath = path;
}

VCL_VOID
vmod_set_unix_path(VRT_CTX, struct vmod_priv *priv, VCL_STRING path)
{
#ifdef HAVE_CURLOPT_UNIX_SOCKET_PATH
	(void)ctx;
	cm_get(priv)->sun_path = path;
#else
	(void)path;
	(void)priv;
	VSLb(ctx->vsl, SLT_Error,
	    "Unix domain socket support not available");
#endif
}

VCL_VOID
vmod_header_add(VRT_CTX, struct vmod_priv *priv, VCL_STRING value)
{
	struct vmod_curl *c;
	struct req_hdr *rh;

	(void)ctx;

	c = cm_get(priv);
	rh = calloc(1, sizeof(struct req_hdr));
	AN(rh);
	rh->value = strdup(value);
	AN(rh->value);
	VTAILQ_INSERT_HEAD(&c->req_headers, rh, list);
}

VCL_VOID
vmod_header_add_all(VRT_CTX, struct vmod_priv *priv)
{
	struct http *hp;
	unsigned u;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	if (VALID_OBJ(ctx->http_bereq, HTTP_MAGIC))
		hp = ctx->http_bereq;
	else if (VALID_OBJ(ctx->http_req, HTTP_MAGIC))
		hp = ctx->http_req;
	else
		return;

	for (u = HTTP_HDR_FIRST; u < hp->nhd; u++) {
		Tcheck(hp->hd[u]);
#define SKIPHDR(n,t) 							\
	if ((size_t)((t).e - (t).b) > strlen(n) &&			\
	    !strncasecmp((n), (t).b, strlen((n))))			\
		continue;
		SKIPHDR("Content-Length:", hp->hd[u]);
		SKIPHDR("Transfer-Encoding:", hp->hd[u]);
#undef SKIPHDR
		vmod_header_add(ctx, priv, hp->hd[u].b);
	}
}

VCL_VOID
vmod_header_remove(VRT_CTX, struct vmod_priv *priv, VCL_STRING header)
{
	struct vmod_curl *c;
	struct req_hdr *rh, *rh2;
	char *split, *s;

	(void)ctx;

	c = cm_get(priv);

	VTAILQ_FOREACH_SAFE(rh, &c->req_headers, list, rh2) {
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
vmod_escape(VRT_CTX, VCL_STRING str)
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
vmod_unescape(VRT_CTX, VCL_STRING str)
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
vmod_proxy(VRT_CTX, struct vmod_priv *priv, VCL_STRING proxy)
{
	(void)ctx;
	vmod_set_proxy(ctx, priv, proxy);
}

VCL_VOID
vmod_set_proxy(VRT_CTX, struct vmod_priv *priv, VCL_STRING proxy)
{
	(void)ctx;
	cm_get(priv)->proxy = proxy;
}

VCL_VOID
vmod_set_method(VRT_CTX, struct vmod_priv *priv, VCL_STRING name)
{
	(void)ctx;
	cm_get(priv)->method = name;
}

VCL_VOID
vmod_set_debug(VRT_CTX, struct vmod_priv *priv, VCL_ENUM what)
{
	struct vmod_curl *c;

	c = cm_get(priv);
	c->vctx = ctx;
#define DBG(u,l,v)	if (!strcmp(what, #l)) c->debug_flags |= v;
#include "debug_flags.h"
#undef DBG
}
