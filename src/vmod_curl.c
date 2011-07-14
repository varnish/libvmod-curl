#include <stdlib.h>
#include <curl/curl.h>
#include <ctype.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"
#include "syslog.h"

struct hdr {
	char *key;
	char *value;
	VTAILQ_ENTRY(hdr) list;
};

struct vmod_curl {
	unsigned	magic;
#define VMOD_CURL_MAGIC 0xBBB0C87C
	long		status;
	const char	*error;
	VTAILQ_HEAD(, hdr) headers;
};

static struct vmod_curl *vmod_curl_list;
int vmod_curl_list_sz;
static pthread_mutex_t cl_mtx = PTHREAD_MUTEX_INITIALIZER;


static void cm_init(struct vmod_curl *c) {
//	printf("zz:%s %d %p \n", __FILE__, __LINE__, c);
	c->magic = VMOD_CURL_MAGIC;
	c->status = 0;
	c->error = NULL;
	VTAILQ_INIT(&c->headers);
}

static void cm_free(struct vmod_curl *c) {
	struct hdr *h;

	if (c->magic != VMOD_CURL_MAGIC) {
		AN(printf("cm_free called with a non-cm object\n"));

	}

	while (!VTAILQ_EMPTY(&c->headers)) {
		h = VTAILQ_FIRST(&c->headers);
		VTAILQ_REMOVE(&c->headers, h, list);
		free(h->key);
		free(h->value);
		free(h);
	}
	VTAILQ_INIT(&c->headers);

	c->status = 0;
	c->error = NULL;
	c->magic = 0;
}

static void cm_copy(struct vmod_curl *dst, struct vmod_curl *src) {
	struct hdr *h;

	dst->magic = VMOD_CURL_MAGIC;
	dst->status = src->status;
	dst->error = src->error;
	VTAILQ_FOREACH(h, &src->headers, list) {
		VTAILQ_INSERT_HEAD(&dst->headers, h, list);
	}
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
	(void)s;
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

	h = malloc(sizeof(struct hdr));
	AN(h);

	keylen = split - (char*)ptr;
	vallen = size*nmemb - keylen;

	h->key = strndup(ptr, keylen);
	split++;
	while (isspace(*split)) {
		split++;
		vallen--;
	}
	e = split+vallen - 1 - 1 ;
	while (isspace(*e)) {
		*e = '\0';
		e--;
		vallen--;
	}
	h->value = strndup(split, vallen);
	AN(h->key);
	AN(h->value);

	VTAILQ_INSERT_HEAD(&vc->headers, h, list);

	return size * nmemb;
}

void vmod_fetch(struct sess *sp, const char *url)
{
	CURL *curl_handle;
	CURLcode cr;

	struct vmod_curl c;
	char *p;
	unsigned u, v;
	struct hdr *h, *h2;

	cm_init(&c);

	curl_handle = curl_easy_init();
	AN(curl_handle);

	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL , 1L);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, recv_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&c);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, recv_hdrs);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *)&c);

	cr = curl_easy_perform(curl_handle);

	if (cr != 0) {
		c.error = curl_easy_strerror(cr);
	}

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &c.status);

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
/*	cm_free(&vmod_curl_list[sp->id]);*/
	cm_init(&vmod_curl_list[sp->id]);
	cm_copy(&vmod_curl_list[sp->id], &c);

/*	VTAILQ_FOREACH_SAFE(h, &c.headers, list, h2) {
		VTAILQ_REMOVE(&c.headers, h, list);
	}
*/
	AZ(pthread_mutex_unlock(&cl_mtx));
	curl_easy_cleanup(curl_handle);
}

int vmod_status(struct sess *sp) {
	int r;
	AZ(pthread_mutex_lock(&cl_mtx));
	r = vmod_curl_list[sp->id].status;
	AZ(pthread_mutex_unlock(&cl_mtx));
	return r;
}

void vmod_free(struct sess *sp) {
	AZ(pthread_mutex_lock(&cl_mtx));
	if (vmod_curl_list_sz >= sp->id)
		cm_free(&vmod_curl_list[sp->id]);
	AZ(pthread_mutex_unlock(&cl_mtx));
}

const char *vmod_error(struct sess *sp) {
	const char *r;
	AZ(pthread_mutex_lock(&cl_mtx));
	if (vmod_curl_list[sp->id].status != 0)
		r = NULL;
	r = vmod_curl_list[sp->id].error;
	AZ(pthread_mutex_unlock(&cl_mtx));
	return r;
}

const char *vmod_header(struct sess *sp, const char *header)
{
	struct hdr *h;
	const char *r = NULL;
	AZ(pthread_mutex_lock(&cl_mtx));

	VTAILQ_FOREACH(h, &vmod_curl_list[sp->id].headers, list) {
		if (strcasecmp(h->key, header) == 0) {
			r = h->value;
			break;
		}
	}
	AZ(pthread_mutex_unlock(&cl_mtx));
	return r;
}
