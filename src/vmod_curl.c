#include <stdlib.h>
#include <curl/curl.h>
#include <ctype.h>

#include "vrt.h"
#include "vsb.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

struct hdr {
	char *key;
	char *value;
	VTAILQ_ENTRY(hdr) list;
};

struct vmod_curl {
	unsigned	magic;
#define VMOD_CURL_MAGIC 0xBBB0C87C
	unsigned xid;
	long		status;
	long		timeout_ms;
	long		connect_timeout_ms;
	const char	*error;
	VTAILQ_HEAD(, hdr) headers;
	struct vsb	*body;
};

static struct vmod_curl *vmod_curl_list;
int vmod_curl_list_sz;
static pthread_mutex_t cl_mtx = PTHREAD_MUTEX_INITIALIZER;

static void cm_init(struct vmod_curl *c) {
	c->magic = VMOD_CURL_MAGIC;
	c->status = 0;
	c->timeout_ms = -1;
	c->connect_timeout_ms = -1;
	c->error = NULL;
	VTAILQ_INIT(&c->headers);
	c->body = VSB_new_auto();
}

static void cm_free(struct vmod_curl *c) {
	struct hdr *h, *h2;

	if (c->magic != VMOD_CURL_MAGIC) {
		AN(printf("cm_free called with a non-cm object\n"));

	}

	VTAILQ_FOREACH_SAFE(h, &c->headers, list, h2) {
		VTAILQ_REMOVE(&c->headers, h, list);
		free(h->key);
		free(h->value);
		free(h);
	}

	c->status = 0;
	c->error = NULL;
	if (c->body)
		VSB_delete(c->body);
	c->body = NULL;
	c->magic = 0;
}

static struct vmod_curl* cm_get(struct sess *sp) {
	struct vmod_curl *cm;
	AZ(pthread_mutex_lock(&cl_mtx));

	while (vmod_curl_list_sz <= sp->id) {
		int ns = vmod_curl_list_sz*2;
		/* resize array */
		vmod_curl_list = realloc(vmod_curl_list, ns * sizeof(struct vmod_curl));
		for (; vmod_curl_list_sz < ns; vmod_curl_list_sz++) {
			cm_init(&vmod_curl_list[vmod_curl_list_sz]);
		}
		assert(vmod_curl_list_sz == ns);
		AN(vmod_curl_list);
	}
	cm = &vmod_curl_list[sp->id];
	if (cm->xid != cm->xid) {
		cm_free(cm);
		cm_init(cm);
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
	vmod_curl_list = malloc(sizeof(struct vmod_curl) * 256);
	AN(vmod_curl_list);
	for (i = 0 ; i < vmod_curl_list_sz; i++) {
		cm_init(&vmod_curl_list[i]);
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
	size_t keylen, vallen;

	CAST_OBJ_NOTNULL(vc, s, VMOD_CURL_MAGIC);

	split = strchr(ptr, ':');
	if (!split) {
	  return size * nmemb;
	}

	h = calloc(1, sizeof(struct hdr));
	AN(h);

	keylen = split - (char*)ptr;
	assert(keylen > 0);
	vallen = size*nmemb - keylen;

	h->key = strndup(ptr, keylen);
	AN(h->key);
	split++;
	while (isspace(*split)) {
		split++;
		vallen--;
	}
	e = split+vallen - 1 - 1 ;
	assert(e > split);
	while (isspace(*e)) {
		*e = '\0';
		e--;
		vallen--;
	}
	assert(vallen > 0 < 100);
	h->value = strndup(split, vallen);
	AN(h->value);

	VTAILQ_INSERT_HEAD(&vc->headers, h, list);

	return size * nmemb;
}

void vmod_fetch(struct sess *sp, const char *url)
{
	CURL *curl_handle;
	CURLcode cr;

	struct vmod_curl *c;
	char *p;
	unsigned u, v;
	struct hdr *h, *h2;

	c = cm_get(sp);

	curl_handle = curl_easy_init();
	AN(curl_handle);

	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL , 1L);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, recv_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)c);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, recv_hdrs);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *)c);

	if (c->timeout_ms > 0)
	  curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, c->timeout_ms);

	if (c->connect_timeout_ms > 0)
	  curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT_MS, c->connect_timeout_ms);

	cr = curl_easy_perform(curl_handle);

	if (cr != 0) {
		c->error = curl_easy_strerror(cr);
	}

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &c->status);

	VSB_finish(c->body);
	curl_easy_cleanup(curl_handle);
}

int vmod_status(struct sess *sp) {
	int r;
	r = cm_get(sp)->status;
	return r;
}

void vmod_free(struct sess *sp) {
	cm_free(cm_get(sp));
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

