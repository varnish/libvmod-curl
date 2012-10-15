#include <stdlib.h>
#include <curl/curl.h>
#include <ctype.h>
#include <stddef.h>

#include "vrt.h"
#include "vsb.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"
#include "vmod_curl.h"

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
	unsigned	magic;
#define VMOD_CURL_MAGIC 0xBBB0C87C
	unsigned xid;
	long		status;
	long		timeout_ms;
	long		connect_timeout_ms;
	char		flags;
#define VC_VERIFY_PEER (1 << 0)
#define VC_VERIFY_HOST (1 << 1)
	const char	*error;
	const char	*cafile;
	const char	*capath;
	VTAILQ_HEAD(, hdr) headers;
	VTAILQ_HEAD(, req_hdr) req_headers;
	struct vsb	*body;
};

static struct vmod_curl **vmod_curl_list;
int vmod_curl_list_sz;
static pthread_mutex_t cl_mtx = PTHREAD_MUTEX_INITIALIZER;

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

static void cm_clear(struct vmod_curl *c) {
	CHECK_OBJ_NOTNULL(c, VMOD_CURL_MAGIC);

	cm_clear_body(c);
	cm_clear_headers(c);
	cm_clear_req_headers(c);
	c->status = 0;
	c->timeout_ms = -1;
	c->connect_timeout_ms = -1;
	c->flags = 0;
	c->cafile = NULL;
	c->capath = NULL;
	c->error = NULL;
	c->xid = 0;
}

static struct vmod_curl* cm_get(struct sess *sp) {
	struct vmod_curl *cm;
	AZ(pthread_mutex_lock(&cl_mtx));

	while (vmod_curl_list_sz <= sp->id) {
		int ns = vmod_curl_list_sz*2;
		/* resize array */
		vmod_curl_list = realloc(vmod_curl_list, ns * sizeof(struct vmod_curl *));
		for (; vmod_curl_list_sz < ns; vmod_curl_list_sz++) {
			vmod_curl_list[vmod_curl_list_sz] = malloc(sizeof(struct vmod_curl));
			cm_init(vmod_curl_list[vmod_curl_list_sz]);
		}
		assert(vmod_curl_list_sz == ns);
		AN(vmod_curl_list);
	}
	cm = vmod_curl_list[sp->id];
	if (cm->xid != sp->xid) {
		cm_clear(cm);
		cm->xid = sp->xid;
	}
	AZ(pthread_mutex_unlock(&cl_mtx));
	return cm;
}

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	int i;

	vmod_curl_list = NULL;
	vmod_curl_list_sz = 256;
	vmod_curl_list = malloc(sizeof(struct vmod_curl *) * 256);
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

	VSB_bcat(vc->body, ptr, size * nmemb);
	return size * nmemb;
}

static size_t recv_hdrs(void *ptr, size_t size, size_t nmemb, void *s)
{
	struct vmod_curl *vc;
	struct hdr *h;
	char *split, *e;
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

void vmod_fetch(struct sess *sp, const char *url)
{
	CURL *curl_handle;
	CURLcode cr;
	struct curl_slist *req_headers = NULL;
	struct req_hdr *rh;

	struct vmod_curl *c;
	char *p;
	unsigned u, v;
	struct hdr *h, *h2;

	c = cm_get(sp);

	cm_clear_headers(c);
	cm_clear_body(c);

	curl_handle = curl_easy_init();
	AN(curl_handle);

	VTAILQ_FOREACH(rh, &c->req_headers, list) {
		req_headers = curl_slist_append(req_headers, rh->value);
	}

	if (req_headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, req_headers);
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL , 1L);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, recv_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, c);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, recv_hdrs);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, c);

	if (c->timeout_ms > 0)
	  curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, c->timeout_ms);

	if (c->connect_timeout_ms > 0)
	  curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT_MS, c->connect_timeout_ms);

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
	}

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &c->status);

	VSB_finish(c->body);

	if (req_headers)
		curl_slist_free_all(req_headers);
	curl_easy_cleanup(curl_handle);
}

int vmod_status(struct sess *sp) {
	int r;
	r = cm_get(sp)->status;
	return r;
}

void vmod_free(struct sess *sp) {
	cm_clear(cm_get(sp));
}

const char *vmod_error(struct sess *sp) {
	struct vmod_curl *c;

	c = cm_get(sp);
	if (c->status != 0)
		return(NULL);
	return(c->error);
}

const char *vmod_header(struct sess *sp, const char *header)
{
	struct hdr *h;
	const char *r = NULL;
	struct vmod_curl *c;

	c = cm_get(sp);

	VTAILQ_FOREACH(h, &c->headers, list) {
		if (strcasecmp(h->key, header) == 0) {
			r = h->value;
			break;
		}
	}
	return r;
}

const char *vmod_body(struct sess *sp) {
	return VSB_data(cm_get(sp)->body);
}

void vmod_set_timeout(struct sess *sp, int timeout) {
	cm_get(sp)->timeout_ms = timeout;
}

void vmod_set_connect_timeout(struct sess *sp, int timeout) {
	cm_get(sp)->connect_timeout_ms = timeout;
}

void vmod_set_ssl_verify_peer(struct sess *sp, int verify) {
	if (verify) {
		cm_get(sp)->flags |= VC_VERIFY_PEER;
	} else {
		cm_get(sp)->flags &= ~VC_VERIFY_PEER;
	}
}

void vmod_set_ssl_verify_host(struct sess *sp, int verify) {
	if (verify) {
		cm_get(sp)->flags |= VC_VERIFY_HOST;
	} else {
		cm_get(sp)->flags &= ~VC_VERIFY_HOST;
	}
}

void vmod_set_ssl_cafile(struct sess *sp, const char *path) {
	cm_get(sp)->cafile = path;
}

void vmod_set_ssl_capath(struct sess *sp, const char *path) {
	cm_get(sp)->capath = path;
}

void vmod_add_header(struct sess *sp, const char *value)
{
	struct vmod_curl *c;
	struct req_hdr *rh;

	c = cm_get(sp);

	rh = calloc(1, sizeof(struct req_hdr));
	AN(rh);
	rh->value = strdup(value);
	AN(rh->value);

	VTAILQ_INSERT_HEAD(&c->req_headers, rh, list);
}

void vmod_unset_header(struct sess *sp, const char *header)
{
	struct vmod_curl *c;
	struct req_hdr *rh;
	char *split, *s;

	c = cm_get(sp);

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

const char *vmod_escape(struct sess *sp, const char *str) {
	char *esc, *r;

	CURL *curl_handle;
	CURLcode cr;

	curl_handle = curl_easy_init();
	AN(curl_handle);

	esc = curl_easy_escape(curl_handle, str, 0);
	AN(esc);
	r = WS_Dup(sp->ws, esc);
	curl_free(esc);
	curl_easy_cleanup(curl_handle);

	return r;
}

const char *vmod_unescape(struct sess *sp, const char *str) {
	char *tmp, *r;

	CURL *curl_handle;
	CURLcode cr;

	curl_handle = curl_easy_init();
	AN(curl_handle);

	tmp = curl_easy_unescape(curl_handle, str, 0, NULL);
	AN(tmp);
	r = WS_Dup(sp->ws, tmp);
	curl_free(tmp);
	curl_easy_cleanup(curl_handle);

	return r;
}
