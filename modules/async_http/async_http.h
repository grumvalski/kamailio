/**
 * Copyright (C) 2014 Daniel-Constantin Mierla (asipto.com)
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _ASYNC_HTTP_
#define _ASYNC_HTTP_

#define RC_AVP_NAME "http_rc"
#define RC_AVP_NAME_LENGTH 7
#define RB_AVP_NAME "http_rb"
#define RB_AVP_NAME_LENGTH 7
#define ERROR_AVP_NAME "http_error"
#define ERROR_AVP_NAME_LENGTH 10

#include <curl/curl.h>
#include <event2/event.h>

#include "../../pvar.h"

#include "http_multi.h"

static int num_workers = 1;

extern int http_timeout; /* query timeout in ms */

typedef struct async_http_worker {
	struct event_base *evbase;
	struct event *socket_event;
	struct http_m_global *g;
} async_http_worker_t;

typedef struct async_query {
	str query;
	str post;
	unsigned int tindex;
	unsigned int tlabel;
	void *param;
} async_query_t;

int async_http_init_sockets(void);
void async_http_close_sockets_parent(void);
void async_http_close_sockets_child(void);
int async_http_init_worker(int prank, async_http_worker_t* worker);
void async_http_run_worker(async_http_worker_t* worker);
int async_send_query(sip_msg_t *msg, str *query, str *post, cfg_action_t *act);
int async_push_query(async_query_t *aq);

void async_http_init_curl(void);
void notification_socket_cb(int fd, short event, void *arg);
int init_socket(async_http_worker_t* worker);
void async_http_cb(struct http_m_reply *reply, void *param);

static inline void free_async_query(async_query_t *aq)
{
	if (!aq)
		return;
	LM_DBG("freeing query %p\n", aq);
	if (aq->query.s && aq->query.len) {
		shm_free(aq->query.s);
		aq->query.s=0;
		aq->query.len=0;
	}

	if (aq->post.s && aq->post.len) {
		shm_free(aq->post.s);
		aq->post.s=0;
		aq->post.len=0;
	}

	shm_free(aq);
}

#endif
