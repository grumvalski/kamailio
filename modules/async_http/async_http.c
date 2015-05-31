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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <event2/event.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../cfg/cfg_struct.h"
#include "../../lib/kcore/faked_msg.h"
#include "../../modules/tm/tm_load.h"

#include "async_http.h"

/* tm */
extern struct tm_binds tmb;

static int _async_http_sockets[2];


static int set_rb_avp(str *result);
static int set_rc_avp(int retcode);
static int set_error_avp(char *error);

void async_http_init_curl(void)
{
    set_curl_mem_callbacks();
}

int async_http_init_worker(int prank, async_http_worker_t* worker)
{
	LM_DBG("initializing worker process: %d\n", prank);
	memset(worker, 0, sizeof(async_http_worker_t));

	worker->evbase = event_base_new();
	LM_DBG("base event %p created\n", worker->evbase);

	worker->g = shm_malloc(sizeof(struct http_m_global));
	memset(worker->g, 0, sizeof(http_m_global_t));
	LM_DBG("initialized global struct %p\n", worker->g);

	init_socket(worker);

	LM_INFO("started worker process: %d\n", prank);

	return 0;
}

void async_http_run_worker(async_http_worker_t* worker)
{
	init_http_multi(worker->evbase, worker->g);
	event_base_dispatch(worker->evbase);
}

int async_http_init_sockets(void)
{
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, _async_http_sockets) < 0) {
		LM_ERR("opening tasks dgram socket pair\n");
		return -1;
	}
	LM_INFO("inter-process event notification sockets initialized\n");
	return 0;
}

void async_http_close_sockets_parent(void)
{
	LM_DBG("closing the notification socket used by parent\n");
	close(_async_http_sockets[0]);
}

void async_http_close_sockets_child(void)
{
	LM_DBG("closing the notification socket used by children\n");
	close(_async_http_sockets[1]);
}

void async_http_cb(struct http_m_reply *reply, void *param)
{
	async_query_t *aq;
	cfg_action_t *act;
	unsigned int tindex;
	unsigned int tlabel;
	struct cell *t = NULL;

	if (reply->result != NULL) {
		LM_DBG("query result = %.*s [%d]", reply->result->len, reply->result->s, reply->result->len);
	}

	aq = param;
	act = (cfg_action_t*)aq->param;
	tindex = aq->tindex;
	tlabel = aq->tlabel;

	if (tmb.t_lookup_ident(&t, tindex, tlabel) < 0) {
		LM_ERR("transaction not found %d:%d\n", tindex, tlabel);
		LM_DBG("freeing query %p\n", aq);
		free_async_query(aq);
		return;
	}
	// we bring the list of AVPs of the transaction to the current context
	set_avp_list(AVP_TRACK_FROM | AVP_CLASS_URI, &t->uri_avps_from);
	set_avp_list(AVP_TRACK_TO | AVP_CLASS_URI, &t->uri_avps_to);
	set_avp_list(AVP_TRACK_FROM | AVP_CLASS_USER, &t->user_avps_from);
	set_avp_list(AVP_TRACK_TO | AVP_CLASS_USER, &t->user_avps_to);
	set_avp_list(AVP_TRACK_FROM | AVP_CLASS_DOMAIN, &t->domain_avps_from);
	set_avp_list(AVP_TRACK_TO | AVP_CLASS_DOMAIN, &t->domain_avps_to);

	if (reply->result != NULL) {
		set_rb_avp(reply->result);
	}
	set_rc_avp(reply->retcode);
	set_error_avp(reply->error);

	if (t)
		tmb.unref_cell(t);

	LM_DBG("resuming transaction (%d:%d)", tindex, tlabel);

	if(act!=NULL)
		tmb.t_continue(tindex, tlabel, act);

	free_async_query(aq);

	return;
}

void notification_socket_cb(int fd, short event, void *arg)
{
	(void)fd; /* unused */
	(void)event; /* unused */

	int received;
	async_query_t *aq;

	str query;
	str post;

	if ((received = recvfrom(_async_http_sockets[0],
			&aq, sizeof(async_query_t*),
			0, NULL, 0)) < 0) {
		LM_ERR("failed to read from socket (%d: %s)\n", errno, strerror(errno));
		return;
	}

	if(received != sizeof(async_query_t*)) {
		LM_ERR("invalid query size %d\n", received);
		return;
	}

	query = ((str)aq->query);
	post = ((str)aq->post);
	LM_DBG("query received: [%.*s] (%p)", query.len, query.s, aq);

	if (new_request(&query, &post, http_timeout, async_http_cb, aq) < 0) {
		LM_ERR("Cannot create request for %.*s", query.len, query.s);
		free_async_query(aq);
	}

	return;
}

int init_socket(async_http_worker_t *worker)
{
	worker->socket_event = event_new(worker->evbase, _async_http_sockets[0], EV_READ|EV_PERSIST, notification_socket_cb, NULL);
	event_add(worker->socket_event, NULL);
	return (0);
}

int async_send_query(sip_msg_t *msg, str *query, str *post, cfg_action_t *act)
{
	async_query_t *aq;
	unsigned int tindex;
	unsigned int tlabel;
	int dsize;
	tm_cell_t *t = 0;

	if(query==0) {
		LM_ERR("invalid parameters\n");
		return -1;
	}

	if(tmb.t_suspend==NULL) {
		LM_ERR("http async query is disabled - tm module not loaded\n");
		return -1;
	}

	t = tmb.t_gett();
	if (t==NULL || t==T_UNDEFINED)
	{
		if(tmb.t_newtran(msg)<0)
		{
			LM_ERR("cannot create the transaction\n");
			return -1;
		}
		t = tmb.t_gett();
		if (t==NULL || t==T_UNDEFINED)
		{
			LM_ERR("cannot lookup the transaction\n");
			return -1;
		}
	}

	if(tmb.t_suspend(msg, &tindex, &tlabel)<0)
	{
		LM_ERR("failed to suspend request processing\n");
		return -1;
	}

	LM_DBG("transaction suspended [%u:%u]\n", tindex, tlabel);

	dsize = sizeof(async_query_t);
	aq = (async_query_t*)shm_malloc(dsize);

	if(aq==NULL)
	{
		LM_ERR("no more shm\n");
		return -1;
	}
	memset(aq,0,dsize);

    if(shm_str_dup(&aq->query, query)<0) {
		goto error;
	}

	if (post != NULL) {

		if(shm_str_dup(&aq->post, post)<0) {
			goto error;
		}
	}

	aq->param = act;
	aq->tindex = tindex;
	aq->tlabel = tlabel;
	if(async_push_query(aq)<0) {
		LM_ERR("failed to relay query: %.*s\n", query->len, query->s);
		goto error;
	}

	return 0;

error:
	tmb.t_cancel_suspend(tindex, tlabel);
	free_async_query(aq);
	return -1;
}

int async_push_query(async_query_t *aq)
{
	int len;

	str query;

	if(num_workers<=0) {
		LM_ERR("no available worker\n");
		return -1;
	}

	query = ((str)aq->query);

	len = write(_async_http_sockets[1], &aq, sizeof(async_query_t*));
	if(len<=0) {
		LM_ERR("failed to pass the query to async workers\n");
		return -1;
	}
	LM_DBG("query sent [%.*s] (%p)\n", query.len, query.s, aq);
	return 0;
}

static int set_rb_avp(str *result)
{
	int rc;
	int_str avp_val, avp_name;
	avp_name.s.s = RB_AVP_NAME;
	avp_name.s.len = RB_AVP_NAME_LENGTH;

	avp_val.s.s = result->s;
	avp_val.s.len = result->len;

	rc = add_avp(AVP_NAME_STR|AVP_VAL_STR, avp_name, avp_val);

   	if (rc < 0)
		LM_ERR("Couldn't create ["RB_AVP_NAME"] AVP\n");
	else
		LM_DBG("Created AVP ["RB_AVP_NAME"] successfully: value=[%.*s]\n", avp_val.s.len, avp_val.s.s);

	return 1;
}

static int set_error_avp(char *error)
{
	int rc;
	int_str avp_val, avp_name;
	avp_name.s.s = ERROR_AVP_NAME;
	avp_name.s.len = ERROR_AVP_NAME_LENGTH;

	avp_val.s.s = error;
	avp_val.s.len = strlen(error);

	rc = add_avp(AVP_NAME_STR|AVP_VAL_STR, avp_name, avp_val);

   	if (rc < 0)
		LM_ERR("Couldn't create ["ERROR_AVP_NAME"] AVP\n");
	else
		LM_DBG("Created AVP ["ERROR_AVP_NAME"] successfully: value=[%.*s]\n", avp_val.s.len, avp_val.s.s);

	return 1;
}

static int set_rc_avp(int retcode)
{
	int rc;
	int_str avp_val, avp_name;
	avp_name.s.s = RC_AVP_NAME;
	avp_name.s.len = RC_AVP_NAME_LENGTH;

	avp_val.n = retcode;

	rc = add_avp(AVP_NAME_STR, avp_name, avp_val);

	if (rc < 0)
		LM_ERR("Couldn't create ["RC_AVP_NAME"] AVP\n");
	else
		LM_DBG("Created AVP ["RC_AVP_NAME"] successfully: value=[%d]\n", avp_val.n);

	return 1;
}
