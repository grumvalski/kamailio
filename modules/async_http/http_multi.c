#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../hashes.h"
#include "http_multi.h"

extern int hash_size;
/*! global http multi table */
struct http_m_table *hm_table = 0;
struct http_m_global *g = 0;

/* Update the event timer after curl_multi library calls */
int multi_timer_cb(CURLM *multi, long timeout_ms, struct http_m_global *g)
{
	struct timeval timeout;
	(void)multi; /* unused */

	timeout.tv_sec = timeout_ms/1000;
	timeout.tv_usec = (timeout_ms%1000)*1000;
	LM_DBG("multi_timer_cb: Setting timeout to %ld ms\n", timeout_ms);
	evtimer_add(g->timer_event, &timeout);
	return 0;
}
/* Called by libevent when our timeout expires */
void timer_cb(int fd, short kind, void *userp)
{
	struct http_m_global *g = (struct http_m_global *)userp;
	CURLMcode rc;
	(void)fd;
	(void)kind;

	char error[CURL_ERROR_SIZE];

	LM_DBG("timeout on socket %d\n", fd);

	rc = curl_multi_socket_action(g->multi,
                                  CURL_SOCKET_TIMEOUT, 0, &g->still_running);
	if (check_mcode(rc, error) < 0) {
		LM_ERR("curl_multi_socket_action error: %s", error);
	}

	check_multi_info(g);
}
/* Called by libevent when we get action on a multi socket */
void event_cb(int fd, short kind, void *userp)
{
	struct http_m_global *g;
	CURLMcode rc;
	CURL *easy = (CURL*) userp;
	struct http_m_cell *cell;

	cell = http_m_cell_lookup(easy);
	if (cell == NULL) {
		LM_INFO("Cell for handler %p not found in table\n", easy);
		return;
	}

	g = cell->global;
	int action =
		(kind & EV_READ ? CURL_CSELECT_IN : 0) |
		(kind & EV_WRITE ? CURL_CSELECT_OUT : 0);

	LM_DBG("activity %d on socket %d: action %d", kind, fd, action);
	if (kind == EV_TIMEOUT) {
		LM_DBG("handle %p timeout on socket %d (cell=%p, param=%p)", cell->easy, fd, cell, cell->param);
		update_stat(timeouts, 1);
		const char *error = "TIMEOUT";

		strncpy(cell->error, error, strlen(error)+1);

		reply_error(cell);

		easy = cell->easy;
		/* we are going to remove the cell and the handle here:
		   pass NULL as sockptr */
		curl_multi_assign(g->multi, cell->sockfd, NULL);

		LM_DBG("cleaning up cell %p", cell);
		if (cell->evset && cell->ev) {
			LM_DBG("freeing event %p", cell->ev);
			event_del(cell->ev);
			event_free(cell->ev);
			cell->ev=NULL;
			cell->evset=0;
		}
		unlink_http_m_cell(cell);
		shm_free(cell->url);
		if (cell->post_data != NULL) {
			shm_free(cell->post_data);
		}
		shm_free(cell);

		LM_DBG("removing handle %p\n", easy);
		curl_multi_remove_handle(g->multi, easy);
		curl_easy_cleanup(easy);
		rc = curl_multi_socket_action(g->multi,
                                  CURL_SOCKET_TIMEOUT, 0, &g->still_running);

	} else {
		LM_DBG("performing action %d on socket %d", action, fd);
		rc = curl_multi_socket_action(g->multi, fd, action, &g->still_running);
		LM_DBG("action %d on socket %d performed", action, fd);

		if (rc == CURLM_CALL_MULTI_PERFORM) {
			LM_DBG("received CURLM_CALL_MULTI_PERFORM, performing action again\n");
			rc = curl_multi_socket_action(g->multi, fd, action, &g->still_running);
		}
		if (check_mcode(rc, cell->error) < 0) {
			LM_ERR("error: %s", cell->error);
			reply_error(cell);
		}
	}

	check_multi_info(g);
	if ( g->still_running <= 0 ) {
		LM_DBG("last transfer done, kill timeout\n");
		if (evtimer_pending(g->timer_event, NULL)) {
			evtimer_del(g->timer_event);
		}
	}
}

/* CURLMOPT_SOCKETFUNCTION */
int sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp)
{
	struct http_m_global *g = (struct http_m_global*) cbp;
	struct http_m_cell *cell = (struct http_m_cell*)sockp;
	const char *whatstr[]={ "none", "IN", "OUT", "INOUT", "REMOVE" };

	LM_DBG("socket callback: s=%d e=%p what=%s ", s, e, whatstr[what]);
	if (what == CURL_POLL_REMOVE) {
		/* if cell is NULL the handle has been removed by the event callback for timeout */
		if (cell) {
			if (cell->evset && cell->ev) {
				LM_DBG("freeing event %p", cell->ev);
				event_del(cell->ev);
				event_free(cell->ev);
				cell->ev=NULL;
				cell->evset=0;
			}
		}
		else {
			LM_DBG("REMOVE action without cell, handler timed out.");
		}
	}
	else {
		if (!cell) {
			LM_DBG("Adding data: %s\n", whatstr[what]);
			addsock(s, e, what, g);
		}
		else {
			LM_DBG("Changing action from %s to %s\n",
			whatstr[cell->action], whatstr[what]);
			setsock(cell, s, e, what);
		}
	}
	return 0;
}
int check_mcode(CURLMcode code, char *error)
{
	const char *s;
	if ( CURLM_OK != code && CURLM_CALL_MULTI_PERFORM != code ) {
		switch (code) {
			case     CURLM_BAD_HANDLE:         s="CURLM_BAD_HANDLE";         break;
			case     CURLM_BAD_EASY_HANDLE:    s="CURLM_BAD_EASY_HANDLE";    break;
			case     CURLM_OUT_OF_MEMORY:      s="CURLM_OUT_OF_MEMORY";      break;
			case     CURLM_INTERNAL_ERROR:     s="CURLM_INTERNAL_ERROR";     break;
			case     CURLM_UNKNOWN_OPTION:     s="CURLM_UNKNOWN_OPTION";     break;
			case     CURLM_LAST:               s="CURLM_LAST";               break;
			case     CURLM_BAD_SOCKET:         s="CURLM_BAD_SOCKET";	   break;
			default: s="CURLM_unknown";
			  break;
		}
		LM_ERR("ERROR: %s\n", s);
		strncpy(error, s, strlen(s)+1);
		return -1;
	}
	return 0;
}
/* CURLOPT_WRITEFUNCTION */
size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
	struct http_m_reply *reply;
	size_t realsize = size * nmemb;
	struct http_m_cell *cell;
	CURL *easy = (CURL*) data;

	LM_DBG("data received: %.*s [%d]", (int)realsize, (char*)ptr, (int)realsize);

	cell = http_m_cell_lookup(easy);
	if (cell == NULL) {
		LM_ERR("Cell for handler %p not found in table\n", easy);
		return -1;
	}

	reply = (struct http_m_reply*)pkg_malloc(sizeof(struct http_m_reply));
	if (reply == NULL) {
		LM_ERR("Cannot allocate pkg memory for reply\n");
		return -1;
	}
	memset( reply, 0, sizeof(struct http_m_reply) );

	reply->result = (str *)pkg_malloc(sizeof(str));
	if (reply->result == NULL) {
		LM_ERR("Cannot allocate pkg memory for reply's result\n");
		pkg_free(reply);
		return -1;
	}
	reply->result->len = realsize;
	reply->result->s = (char*)pkg_malloc(reply->result->len);
	if (reply->result->s == NULL) {
		LM_ERR("Cannot allocate pkg memory for reply's result\n");
		pkg_free(reply->result);
		pkg_free(reply);
		return -1;
	}
	strncpy(reply->result->s, ptr, reply->result->len);

	if (cell->easy == NULL ) {
		LM_DBG("cell %p easy handler is null\n", cell);
	}
	else {
		LM_DBG("getting easy handler info (%p)\n", cell->easy);
		curl_easy_getinfo(cell->easy, CURLINFO_HTTP_CODE, &reply->retcode);
	}


	reply->error[0] = '\0';
	LM_DBG("reply: [%d] %.*s [%d]", (int)reply->retcode, reply->result->len, reply->result->s, reply->result->len);
	update_stat(replies, 1);
	cell->cb(reply, cell->param);

	pkg_free(reply->result->s);
	pkg_free(reply->result);
	pkg_free(reply);

	return realsize;
}

void reply_error(struct http_m_cell *cell)
{
	struct http_m_reply *reply;
	LM_DBG("replying error for  cell=%p", cell);

	reply = (struct http_m_reply*)pkg_malloc(sizeof(struct http_m_reply));
	if (reply == NULL) {
		LM_ERR("Cannot allocate pkg memory for reply's result\n");
		return;
	}
	memset( reply, 0, sizeof(struct http_m_reply) );
	reply->result = NULL;
	reply->retcode = 0;

	if (cell && cell->error != NULL) {
		strncpy(reply->error, cell->error, strlen(cell->error));
		reply->error[strlen(cell->error)] = '\0';
	} else {
		reply->error[0] = '\0';
	}

	cell->cb(reply, cell->param);

	pkg_free(reply);

	return;
}

static void *k_malloc(size_t size)
{
    void *p = shm_malloc(size);
    return p;
}
static void k_free(void *ptr)
{
	if (ptr)
		shm_free(ptr);
}

static void *k_realloc(void *ptr, size_t size)
{
    void *p = shm_realloc(ptr, size);

    return p;
}

static void *k_calloc(size_t nmemb, size_t size)
{
    void *p = shm_malloc(nmemb * size);
    if (p)
        memset(p, '\0', nmemb * size);

    return p;
}

static char *k_strdup(const char *cp)
{
    char *rval;
    int len;

    len = strlen(cp) + 1;
    rval = shm_malloc(len);
    if (!rval)
        return NULL;

    memcpy(rval, cp, len);
    return rval;
}

void set_curl_mem_callbacks(void)
{
	CURLMcode rc;
	LM_DBG("Setting memory callbacks for cURL\n");
    rc = curl_global_init_mem(CURL_GLOBAL_ALL,
                        k_malloc,
                        k_free,
                        k_realloc,
                        k_strdup,
                        k_calloc);
	if (rc != 0) {
		LM_ERR("Cannot set memory callbacks for cURL: %d\n", rc);
	}
}

int init_http_multi(struct event_base *evbase, struct http_m_global *wg)
{
	g = wg;
	g->evbase = evbase;

	set_curl_mem_callbacks();

	g->multi = curl_multi_init();
	LM_DBG("curl_multi %p initialized on global %p (evbase %p)\n", g->multi, g, evbase);

    g->timer_event = evtimer_new(g->evbase, timer_cb, g);

	/* setup the generic multi interface options we want */
	curl_multi_setopt(g->multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
	curl_multi_setopt(g->multi, CURLMOPT_SOCKETDATA, g);
	curl_multi_setopt(g->multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
	curl_multi_setopt(g->multi, CURLMOPT_TIMERDATA, g);

    //return init_http_m_table(HTTP_M_HASH_SIZE);
	return init_http_m_table(hash_size);
}

int new_request(str *query, str *post, int timeout, http_multi_cbe_t cb, void *param)
{

	LM_DBG("received query %.*s with timeout %d (param=%p)", query->len, query->s, timeout, param);
	CURL *easy;
	CURLMcode rc;

	struct http_m_cell *cell;

	update_stat(requests, 1);

    easy = NULL;
    cell = NULL;

	easy = curl_easy_init();
	if (!easy) {
		LM_ERR("curl_easy_init() failed!\n");
		update_stat(errors, 1);
		return -1;
	}

	cell = build_http_m_cell(easy);
	if (!cell) {
		LM_ERR("cannot create cell!\n");
		update_stat(errors, 1);
		LM_DBG("cleaning up curl handler %p", easy);
		curl_easy_cleanup(easy);
		return -1;
	}

	link_http_m_cell(cell);

	cell->global = g;
	cell->easy=easy;
	cell->error[0] = '\0';
	cell->timeout = timeout;
	cell->param = param;
	cell->cb = cb;
	cell->url = (char*)shm_malloc(query->len + 1);
	if (cell->url==0) {
		LM_ERR("no more shm mem\n");
        goto error;
	}
	strncpy(cell->url, query->s, query->len);
	cell->url[query->len] = '\0';

	curl_easy_setopt(cell->easy, CURLOPT_URL, cell->url);
	curl_easy_setopt(cell->easy, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(cell->easy, CURLOPT_WRITEDATA, easy);
	curl_easy_setopt(cell->easy, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(cell->easy, CURLOPT_ERRORBUFFER, cell->error);
	curl_easy_setopt(cell->easy, CURLOPT_PRIVATE, cell);

	if (post && post->s && post->len) {
		curl_easy_setopt(cell->easy, CURLOPT_POST, 1L);
		cell->post_data = shm_malloc(post->len + 1);
		if (cell->post_data == NULL) {
			LM_ERR("cannot allocate pkg memory for post\n");
            goto error;
		}
		strncpy(cell->post_data, post->s, post->len);
		cell->post_data[post->len] = '\0';
		curl_easy_setopt(cell->easy, CURLOPT_POSTFIELDS, cell->post_data);
	}

	LM_DBG("Adding easy %p to multi %p (%.*s)\n", cell->easy, g->multi, query->len, query->s);
	rc = curl_multi_add_handle(g->multi, cell->easy);
	if (check_mcode(rc, cell->error) < 0) {
		LM_ERR("error adding curl handler: %s", cell->error);
        goto error;
	}
	/* note that the add_handle() will set a time-out to trigger very soon so
	 *      that the necessary socket_action() call will be called by this app */
	return 0;

error:
	update_stat(errors, 1);
    if (easy) {
		LM_DBG("cleaning up curl handler %p", easy);
		curl_easy_cleanup(easy);
    }
    if (cell) {
		reply_error(cell);
		unlink_http_m_cell(cell);
        if (cell->url) {
            shm_free(cell->url);
        }
        if (cell->post_data) {
            shm_free(cell->post_data);
        }
        shm_free(cell);
    }
    return -1;
}

/* Check for completed transfers, and remove their easy handles */
void check_multi_info(struct http_m_global *g)
{
	char *eff_url;
	CURLMsg *msg;
	int msgs_left;
	CURL *easy;
	CURLcode res;

	struct http_m_cell *cell;

	LM_DBG("REMAINING: %d\n", g->still_running);
	while ((msg = curl_multi_info_read(g->multi, &msgs_left))) {
		if (msg->msg == CURLMSG_DONE) {
			easy = msg->easy_handle;
			res = msg->data.result;
			curl_easy_getinfo(easy, CURLINFO_PRIVATE, &cell);
			curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &eff_url);
			LM_DBG("DONE: %s => (%d) %s\n", eff_url, res, cell->error);

			cell = http_m_cell_lookup(easy);
			if (msg->data.result != 0) {
				LM_ERR("handle %p returned error %d: %s", easy, res, cell->error);
				update_stat(errors, 1);
				reply_error(cell);
			}
			if (cell != 0) {
				LM_DBG("cleaning up cell %p", cell);
				unlink_http_m_cell(cell);
				shm_free(cell->url);
				if (cell->post_data != NULL) {
					shm_free(cell->post_data);
				}
				shm_free(cell);
			}

			LM_DBG("Removing handle %p\n", easy);
			curl_multi_remove_handle(g->multi, easy);
			curl_easy_cleanup(easy);
		}
	}
}

/* set cell's socket information and assign an event to the socket */
void setsock(struct http_m_cell *cell, curl_socket_t s, CURL*e, int act)
{

	struct timeval timeout;

	int kind =
		(act&CURL_POLL_IN?EV_READ:0)|(act&CURL_POLL_OUT?EV_WRITE:0)|EV_PERSIST;
	struct http_m_global *g = cell->global;
	cell->sockfd = s;
	cell->action = act;
	cell->easy = e;
	if (cell->evset && cell->ev) {
		event_del(cell->ev);
		event_free(cell->ev);
		cell->ev=NULL;
		cell->evset=0;
	}
	cell->ev = event_new(g->evbase, cell->sockfd, kind, event_cb, e);
	LM_DBG("added event %p to socket %d", cell->ev, cell->sockfd);
	cell->evset = 1;


	timeout.tv_sec = cell->timeout/1000;
	timeout.tv_usec = (cell->timeout%1000)*1000;

	event_add(cell->ev, &timeout);
	//event_add(cell->ev, NULL);
}



/* assign a socket to the multi handler */
void addsock(curl_socket_t s, CURL *easy, int action, struct http_m_global *g)
{
	struct http_m_cell *cell;

	cell = http_m_cell_lookup(easy);
	if (!cell)
		return;
	setsock(cell, s, cell->easy, action);
	curl_multi_assign(g->multi, s, cell);
}

