/**
 * Copyright (C) 2014 Federico Cabiddu
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

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../pvar.h"
#include "../../mem/shm_mem.h"
#include "../../mod_fix.h"
#include "../../pvar.h"
#include "../../cfg/cfg_struct.h"
#include "../../lib/kcore/faked_msg.h"

#include "../../modules/tm/tm_load.h"

#include "async_http.h"

MODULE_VERSION

extern int  num_workers;

async_http_worker_t *workers;

int http_timeout = 500; /* query timeout in ms */
int hash_size = 2048;

static int  mod_init(void);
static int  child_init(int);
static void mod_destroy(void);

static int w_http_async_get(sip_msg_t* msg, char* query, char* rt);
static int w_http_async_post(sip_msg_t* msg, char* query, char* post, char* rt);
static int fixup_http_async_get(void** param, int param_no);
static int fixup_http_async_post(void** param, int param_no);

/* tm */
struct tm_binds tmb;

stat_var *requests;
stat_var *replies;
stat_var *errors;
stat_var *timeouts;

static cmd_export_t cmds[]={
	{"http_async_get",  (cmd_function)w_http_async_get, 2, fixup_http_async_get,
		0, ANY_ROUTE},
	{"http_async_post", (cmd_function)w_http_async_post, 3, fixup_http_async_post,
		0, ANY_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static param_export_t params[]={
	{"workers",      INT_PARAM,   &num_workers},
	{"http_timeout", INT_PARAM,   &http_timeout},
    {"hash_size",   INT_PARAM,  &hash_size},
	{0, 0, 0}
};

/*! \brief We expose internal variables via the statistic framework below.*/
stat_export_t mod_stats[] = {
        {"requests",    STAT_NO_RESET, &requests        },
        {"replies", 	STAT_NO_RESET, &replies 	},
        {"errors",      STAT_NO_RESET, &errors       	},
        {"timeouts",    STAT_NO_RESET, &timeouts	},
        {0, 0, 0}
};

struct module_exports exports = {
	"async_http",
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,
	params,
	mod_stats,   	/* exported statistics */
	0,              /* exported MI functions */
	0,              /* exported pseudo-variables */
	0,              /* extra processes */
	mod_init,       /* module initialization function */
	0,              /* response function */
	mod_destroy,    /* destroy function */
	child_init      /* per child init function */
};



/**
 * init module function
 */
static int mod_init(void)
{
	unsigned int n;
	LM_INFO("Initializing Http Async module\n");

#ifdef STATISTICS
	/* register statistics */
	if (register_module_stats( exports.name, mod_stats)!=0 ) {
		LM_ERR("failed to register core statistics\n");
		return -1;
	}
#endif
	/* sanitize hash_size */
	if (hash_size < 1){
		LM_WARN("hash_size is smaller "
				"than 1  -> rounding from %d to 1\n",
				hash_size);
				hash_size = 1;
	}
	/* check that the hash table size is a power of 2 */
	for( n=0 ; n<(8*sizeof(n)) ; n++) {
		if (hash_size==(1<<n))
			break;
		if (n && hash_size<(1<<n)) {
			LM_WARN("hash_size is not a power "
				"of 2 as it should be -> rounding from %d to %d (n=%d)\n",
				hash_size, 1<<(n-1), n);
			hash_size = 1<<(n-1);
			break;
		}
	}
	/* init faked sip msg */
	if(faked_msg_init()<0) {
		LM_ERR("failed to init faked sip msg\n");
		return -1;
	}

	if(load_tm_api( &tmb ) < 0) {
		LM_INFO("cannot load the TM-functions - async relay disabled\n");
		memset(&tmb, 0, sizeof(tm_api_t));
	}

	async_http_init_curl();

	/* allocate workers array */
	workers = shm_malloc(num_workers * sizeof(*workers));
	if(workers == NULL) {
		LM_ERR("error in shm_malloc\n");
		return -1;
	}

	register_procs(num_workers);

	/* add child to update local config framework structures */
	cfg_register_child(num_workers);

	return 0;
}

/**
 * @brief Initialize async module children
 */
static int child_init(int rank)
{
	int pid;
	int i;

	LM_DBG("child initializing async http\n");

	if(num_workers<=0)
		return 0;

	if (rank==PROC_INIT) {
		if(async_http_init_sockets()<0) {
			LM_ERR("failed to initialize tasks sockets\n");
			return -1;
		}
		return 0;
	}

	if(rank>0) {
		async_http_close_sockets_parent();
		return 0;
	}
	if (rank!=PROC_MAIN)
		return 0;

	for(i=0; i<num_workers; i++) {
		if(async_http_init_worker(i+1, &workers[i])<0) {
			LM_ERR("failed to initialize worker process: %d\n", i);
			return -1;
		}
		pid=fork_process(PROC_RPC, "Http Worker", 1);
		if (pid<0)
			return -1; /* error */
		if(pid==0) {
			/* child */
			/* initialize the config framework */
			if (cfg_child_init())
				return -1;
			/* main function for workers */
			async_http_run_worker(&workers[i]);
		}
	}

	return 0;
}

/**
 * destroy module function
 */
static void mod_destroy(void)
{
}

/**
 *
 */
static int w_http_async_get(sip_msg_t *msg, char *query, char* rt)
{
	str sdata;
	cfg_action_t *act;
	str rn;
	int ri;

	if(msg==NULL)
		return -1;

	if(fixup_get_svalue(msg, (gparam_t*)query, &sdata)!=0) {
		LM_ERR("unable to get data\n");
		return -1;
	}
	if(sdata.s==NULL || sdata.len == 0) {
		LM_ERR("invalid data parameter\n");
		return -1;
	}

	if(fixup_get_svalue(msg, (gparam_t*)rt, &rn)!=0)
	{
		LM_ERR("no route block name\n");
		return -1;
	}

	ri = route_get(&main_rt, rn.s);
	if(ri<0)
	{
		LM_ERR("unable to find route block [%.*s]\n", rn.len, rn.s);
		return -1;
	}
	act = main_rt.rlist[ri];
	if(act==NULL)
	{
		LM_ERR("empty action lists in route block [%.*s]\n", rn.len, rn.s);
		return -1;
	}

	if(async_send_query(msg, &sdata, NULL, act)<0)
		return -1;

	/* force exit in config */
	return 0;
}

/**
 *
 */
static int w_http_async_post(sip_msg_t *msg, char *query, char* post, char* rt)
{
	str sdata;
	str post_data;
	cfg_action_t *act;
	str rn;
	int ri;

	if(msg==NULL)
		return -1;

	if(fixup_get_svalue(msg, (gparam_t*)query, &sdata)!=0) {
		LM_ERR("unable to get data\n");
		return -1;
	}

	if(sdata.s==NULL || sdata.len == 0) {
		LM_ERR("invalid data parameter\n");
		return -1;
	}

	if(fixup_get_svalue(msg, (gparam_t*)post, &post_data)!=0) {
		LM_ERR("unable to get post data\n");
		return -1;
	}

	if(post_data.s==NULL || post_data.len == 0) {
		LM_ERR("invalid post data parameter\n");
		return -1;
	}

	if(fixup_get_svalue(msg, (gparam_t*)rt, &rn)!=0)
	{
		LM_ERR("no route block name\n");
		return -1;
	}

	ri = route_get(&main_rt, rn.s);
	if(ri<0)
	{
		LM_ERR("unable to find route block [%.*s]\n", rn.len, rn.s);
		return -1;
	}
	act = main_rt.rlist[ri];
	if(act==NULL)
	{
		LM_ERR("empty action lists in route block [%.*s]\n", rn.len, rn.s);
		return -1;
	}

	if(async_send_query(msg, &sdata, &post_data, act)<0)
		return -1;

	/* force exit in config */
	return 0;
}

/**
 *
 */
static int fixup_http_async_get(void** param, int param_no)
{
	if (param_no == 1) {
		return fixup_spve_null(param, 1);
	}
	if (param_no == 2) {
		return fixup_var_str_12(param, param_no);
	}

	LM_ERR("invalid parameter number <%d>\n", param_no);
	return -1;
}

/**
 *
 */
static int fixup_http_async_post(void** param, int param_no)
{
	if (param_no == 1 || param_no == 2) {
		return fixup_spve_null(param, 1);
	}
	if (param_no == 3) {
		return fixup_var_str_12(param, param_no);
	}

	LM_ERR("invalid parameter number <%d>\n", param_no);
	return -1;
}
