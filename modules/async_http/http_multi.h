#ifndef _HTTP_MULTI_
#define _HTTP_MULTI_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/poll.h>
#include <curl/curl.h>
#include <event2/event.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "../../lib/kcore/statistics.h"
#include "hm_hash.h"


extern stat_var *requests;
extern stat_var *replies;
extern stat_var *errors;
extern stat_var *timeouts;

void  set_curl_mem_callbacks(void);
int init_http_multi();
int multi_timer_cb(CURLM *multi, long timeout_ms, struct http_m_global *g);
void timer_cb(int fd, short kind, void *userp);
int sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp);
int check_mcode(CURLMcode code, char *error);
int new_request(str *query, str *post, int timeout, http_multi_cbe_t cb, void *param);
void check_multi_info(struct http_m_global *g);
void setsock(struct http_m_cell *cell, curl_socket_t s, CURL* e, int act);
void addsock(curl_socket_t s, CURL *easy, int action, struct http_m_global *g);
void event_cb(int fd, short kind, void *userp);
void reply_error(struct http_m_cell *cell);

#endif
