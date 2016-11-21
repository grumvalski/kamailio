/*
 * $Id: mod.c 780 2009-12-01 08:49:52Z aon $
 *	
 * Copyright (C) 2004-2009 FhG Fokus
 *
 * This file is part of Open IMS Core - an open source IMS CSCFs & HSS
 * implementation
 *
 * Open IMS Core is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For a license to use the Open IMS Core software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact Fraunhofer FOKUS by e-mail at the following
 * addresses:
 *	   info@open-ims.org
 *
 * Open IMS Core is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * It has to be noted that this Open Source IMS Core System is not 
 * intended to become or act as a product in a commercial context! Its 
 * sole purpose is to provide an IMS core reference implementation for 
 * IMS technology testing and IMS application prototyping for research 
 * purposes, typically performed in IMS test-beds.
 * 
 * Users of the Open Source IMS Core System have to be aware that IMS
 * technology may be subject of patents and licence terms, as being 
 * specified within the various IMS-related IETF, ITU-T, ETSI, and 3GPP
 * standards. Thus all Open IMS Core users have to take notice of this 
 * fact and have to agree to check out carefully before installing, 
 * using and extending the Open Source IMS Core System, if related 
 * patents and licences may become applicable to the intended usage 
 * context.  
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 */

#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../sr_module.h"
#include "../../socket_info.h"
#include "../../mod_fix.h"
#include "../../cfg/cfg_struct.h"
#include "../../rpc_lookup.h"
#include "../../timer.h"
#include "../../parser/parse_from.h"

#include "../../lib/ims/ims_getters.h"

#include "../ims_usrloc_pcscf/usrloc.h"
#include "../../modules/tm/tm_load.h"
#include "../../modules/sl/sl.h"

#include "pcscf_em_mod.h"
#include "emerg.h"
#include "p_em_rpc.h"
/*
#include "registration.h"
#include "registrar_storage.h"
#include "registrar_subscribe.h"
#include "registrar.h"
#include "nat_helper.h"
#include "security.h"
#include "dlg_state.h"
#include "sdp_util.h"
#include "p_persistency.h"
#include "release_call.h"
#include "ims_pm_pcscf.h"
#include "policy_control.h"
#include "pcc.h"
*/

MODULE_VERSION

static int mod_init(void);
static void mod_destroy(void);

static int w_accept_anonym_em_call(struct sip_msg *msg, char *str1, char *str2);
static int w_is_anonymous_user(struct sip_msg *msg,char *str1,char *str2);
static int w_emergency_flag(struct sip_msg *msg,char *str1,char *str2); 
static int w_380_em_alternative_serv(struct sip_msg * msg, char* str1, char* str2);
static int w_emergency_serv_enabled(struct sip_msg *msg,char *str1,char*str2);
static int w_is_emergency_ruri(struct sip_msg *msg, char *str1, char *str2);
static int w_select_ecscf(struct sip_msg *msg,char *str1,char*str2);
static int w_enforce_sos_routes(struct sip_msg *msg,char *str1,char*str2);
static int w_is_em_registered(struct sip_msg *msg,char *str1,char *str2);
static int w_add_em_path(struct sip_msg * msg, char* str1, char* str2);
static int w_check_em_path(struct sip_msg * msg, char * str1, char * str2);

static int fixup_380_alt_serv(void** param, int param_no);

char* ecscf_uri = "";				/** the e-cscf uri*/
str ecscf_uri_str;
int emerg_support = 1;
int anonym_em_call_support = 1;
char* emerg_numbers_file = CFG_DIR"emerg_info.xml";
str pcscf_path_orig_em_uri_str={0,0};
char * pcscf_path_orig_em_uri = "Path: sip:orig.em@pcscf.open-ims.test\r\n";

static cmd_export_t cmds[]={
	/*emergency services exported functions*/
	{"accept_anonym_em_call",	w_accept_anonym_em_call,	0, 0, 0, REQUEST_ROUTE},
	{"is_anonymous_user",		w_is_anonymous_user,		0, 0, 0, REQUEST_ROUTE},
	{"emergency_flag",			w_emergency_flag,			0, 0, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"380_em_alternative_serv",	w_380_em_alternative_serv,	1, fixup_380_alt_serv, 0, REQUEST_ROUTE},
	{"is_emergency_ruri",		w_is_emergency_ruri,		0, 0, 0, REQUEST_ROUTE},
	{"emergency_serv_enabled",	w_emergency_serv_enabled,	0, 0, 0, REQUEST_ROUTE},
	{"select_ecscf",			w_select_ecscf,				0, 0, 0, REQUEST_ROUTE},
	{"enforce_sos_routes",		w_enforce_sos_routes,		0, 0, 0, REQUEST_ROUTE},
	{"is_em_registered",		w_is_em_registered,			0, 0, 0, REQUEST_ROUTE},
	{"add_em_path",				w_add_em_path,				0, 0, 0, REQUEST_ROUTE},
	{"check_em_path",			w_check_em_path,			0, 0, 0, REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE},
	{0, 0, 0, 0, 0}
}; 

static param_export_t params[]={ 
	{"ecscf_uri",						STR_PARAM, &ecscf_uri},
	{"emerg_support",					INT_PARAM, &emerg_support},
	{"anonym_em_call_support",			INT_PARAM, &anonym_em_call_support},
	{"emerg_numbers_file",				STR_PARAM, &emerg_numbers_file},
	{"pcscf_path_orig_em_uri",			STR_PARAM, &pcscf_path_orig_em_uri},
	{0,0,0} 
};

/*! \brief
 *	* Module exports structure
 *	 */
struct module_exports exports = {
	"ims_emergency_pcscf",
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,			/* Exported functions */
	params,			/* Exported parameters */
	0,		/* exported statistics */
	0,				/* exported MI functions */
	0,		  /* exported pseudo-variables */
	0,				/* extra processes */
	mod_init,		/* module initialization function */
	0,
	mod_destroy,	/* destroy function */
	0,		/* Per-child init function */
};
/* Global variables and imported functions */
										/**< link to the stateless reply function in sl module */

struct tm_binds tmb;					/**!< Structure with pointers to tm funcs		*/
usrloc_api_t ul;						/**!< Structure containing pointers to usrloc functions*/ 
sl_api_t slb;							/**!< SL API structure */ 

/**
 * Fix the configuration parameters.
 */
//int fix_parameters()
//{
//	str x;	
//		
//	pcscf_name_str.s = pcscf_name;
//	pcscf_name_str.len = strlen(pcscf_name);	
//	
//	x = pcscf_name_str;
//	if (pcscf_name_str.len>=4 &&
//		strncasecmp(pcscf_name_str.s,"sip:",4)==0) 
//	{
//		x.s += 4;
//		x.len -= 4;	
//	}
//	pcscf_path_str.len = path_str_1.len+x.len;
//	pcscf_path_str.s = pkg_malloc(pcscf_path_str.len);
//	if (!pcscf_path_str.s){
//		LOG(L_ERR, "ERR"M_NAME":mod_init: Error allocating %d bytes\n",
//			pcscf_path_str.len);
//		pcscf_path_str.len=0;
//		return 0;
//	}
//	pcscf_path_str.len=0;
//	STR_APPEND(pcscf_path_str,path_str_1);
//	STR_APPEND(pcscf_path_str,x);
//
//	pcscf_path_hdr_str.len = path_str_s.len + pcscf_path_str.len + path_str_e.len;
//	pcscf_path_hdr_str.s = pkg_malloc(pcscf_path_hdr_str.len);
//	if (!pcscf_path_hdr_str.s){
//		LOG(L_ERR, "ERR"M_NAME":mod_init: Error allocating %d bytes\n",
//			pcscf_path_hdr_str.len);
//		pcscf_path_hdr_str.len=0;
//		return 0;
//	}
//	pcscf_path_hdr_str.len=0;
//	STR_APPEND(pcscf_path_hdr_str,path_str_s);	
//	STR_APPEND(pcscf_path_hdr_str,pcscf_path_str);
//	STR_APPEND(pcscf_path_hdr_str,path_str_e);
//		
//	cscf_icid_value_prefix_str.s = cscf_icid_value_prefix;
//	cscf_icid_value_prefix_str.len = strlen(cscf_icid_value_prefix);
//
//	cscf_icid_gen_addr_str.s = cscf_icid_gen_addr;
//	cscf_icid_gen_addr_str.len = strlen(cscf_icid_gen_addr);
//	
//	cscf_orig_ioi_str.s = cscf_orig_ioi;
//	cscf_orig_ioi_str.len = strlen(cscf_orig_ioi);
//	
//	cscf_term_ioi_str.s = cscf_term_ioi;
//	cscf_term_ioi_str.len = strlen(cscf_term_ioi);
//
//
//	/* Record-routes */
//	pcscf_record_route_mo.s = pkg_malloc(s_record_route_s.len+s_mo.len+pcscf_name_str.len+s_record_route_lr.len+s_record_route_e.len);
//	if (!pcscf_record_route_mo.s){
//		LOG(L_ERR, "ERR"M_NAME":mod_init: Error allocating %d bytes\n",
//			s_record_route_s.len+s_mo.len+pcscf_name_str.len+s_record_route_lr.len+s_record_route_e.len);
//		return 0;
//	}
//	pcscf_record_route_mt.s = pkg_malloc(s_record_route_s.len+s_mt.len+pcscf_name_str.len+s_record_route_lr.len+s_record_route_e.len);
//	if (!pcscf_record_route_mt.s){
//		LOG(L_ERR, "ERR"M_NAME":mod_init: Error allocating %d bytes\n",
//			s_record_route_s.len+s_mt.len+pcscf_name_str.len+s_record_route_lr.len+s_record_route_e.len);
//		return 0;
//	}
//	
//	pcscf_record_route_mo.len=0;
//	STR_APPEND(pcscf_record_route_mo,s_record_route_s);
//	if (pcscf_name_str.len>4 && strncasecmp(pcscf_name_str.s,"sip:",4)==0){
//		STR_APPEND(pcscf_record_route_mo,s_mo);
//		memcpy(pcscf_record_route_mo.s+pcscf_record_route_mo.len,pcscf_name_str.s+4,
//			pcscf_name_str.len-4);
//		pcscf_record_route_mo.len += pcscf_name_str.len-4;
//	} else {
//		STR_APPEND(pcscf_record_route_mo,s_mo);
//		STR_APPEND(pcscf_record_route_mo,pcscf_name_str);
//	}
//	STR_APPEND(pcscf_record_route_mo,s_record_route_lr);
//	STR_APPEND(pcscf_record_route_mo,s_record_route_e);
//	pcscf_record_route_mo_uri.s = pcscf_record_route_mo.s + s_record_route_s.len;
//	pcscf_record_route_mo_uri.len = pcscf_record_route_mo.len - s_record_route_s.len - s_record_route_e.len;
//
//	pcscf_record_route_mt.len=0;
//	STR_APPEND(pcscf_record_route_mt,s_record_route_s);
//	if (pcscf_name_str.len>4 && strncasecmp(pcscf_name_str.s,"sip:",4)==0){
//		STR_APPEND(pcscf_record_route_mt,s_mt);
//		memcpy(pcscf_record_route_mt.s+pcscf_record_route_mt.len,pcscf_name_str.s+4,
//			pcscf_name_str.len-4);
//		pcscf_record_route_mt.len += pcscf_name_str.len-4;
//	} else {
//		STR_APPEND(pcscf_record_route_mt,s_mt);
//		STR_APPEND(pcscf_record_route_mt,pcscf_name_str);
//	}
//	STR_APPEND(pcscf_record_route_mt,s_record_route_lr);
//	STR_APPEND(pcscf_record_route_mt,s_record_route_e);
//	pcscf_record_route_mt_uri.s = pcscf_record_route_mt.s + s_record_route_s.len;
//	pcscf_record_route_mt_uri.len = pcscf_record_route_mt.len - s_record_route_s.len - s_record_route_e.len;
//
//	/* fix the parameters */
//	forced_clf_peer_str.s = forced_clf_peer;
//	forced_clf_peer_str.len = strlen(forced_clf_peer);
//
//	/* Address initialization of PDF for policy control */
//	forced_qos_peer.s = pcscf_forced_qos_peer;
//	forced_qos_peer.len = strlen(pcscf_forced_qos_peer);
//	
//	if(emerg_support){
//		ecscf_uri_str.s = ecscf_uri;
//		ecscf_uri_str.len = strlen(ecscf_uri);
//		LOG(L_INFO, "INFO"M_NAME":mod_init: E-CSCF uri is %.*s\n", ecscf_uri_str.len, ecscf_uri_str.s);
//	}
//
//	ip_address_for_signaling.s = ip_address_for_signaling_char;
//	ip_address_for_signaling.len = strlen(ip_address_for_signaling_char);
//
//	pcscf_path_orig_em_uri_str.s = pcscf_path_orig_em_uri;
//	pcscf_path_orig_em_uri_str.len = strlen(pcscf_path_orig_em_uri);
//	
//	return 1;
//}

/**
 * Initializes the module.
 */
static int mod_init(void)
{
	bind_usrloc_t bind_usrloc;
	LM_INFO("Module initialization\n");

	/* bind the SL API */
	if (sl_load_api(&slb) != 0) {
		LM_ERR("cannot bind to SL API\n");
		return -1;
	}

	/* load the TM API */
	if (load_tm_api(&tmb) != 0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	bind_usrloc = (bind_usrloc_t) find_export("ul_bind_ims_usrloc_pcscf", 1, 0);
    if (!bind_usrloc || bind_usrloc(&ul) < 0)  {
		LM_ERR("can't bind ims_usrloc_pcscf\n");
		return -1;
    }

	/* register the RPC methods */                                                                                                     
    if(rpc_register_array(rpc_methods)!=0)                                                                                             
    {                                                                                                                                  
        LM_ERR("failed to register RPC commands\n");                                                                                   
        return -1;                                                                                                                     
    }

	/* initializing the variables needed for the Emergency Services support*/
	if (init_emergency_cntxt()<0){
		LM_ERR("error on init_emergency_cntxt()\n");
		return -1;
	}
	return 0;
}

/**
 * Destroys the module.
 */
static void mod_destroy(void)
{
}

static int w_accept_anonym_em_call(struct sip_msg *msg, char *str1, char *str2) {
	
	LM_DBG("Check if the P-CSCF is configured to accept an anonymous emergency call or not\n");
	if(anonym_em_call_support)	
		return CSCF_RETURN_TRUE;
	else	
		return CSCF_RETURN_FALSE;
}

static int w_is_anonymous_user(struct sip_msg *msg,char *str1,char *str2) {
	struct to_body * from_body;
	
	if((!msg->from || !msg->from->parsed) && (parse_from_header(msg)<0))
		return CSCF_RETURN_BREAK;

	from_body = (struct to_body*)msg->from->parsed;
	if((from_body->display.len == anonym_display.len) &&
			(strncmp(from_body->display.s, anonym_display.s, anonym_display.len)==0)){
		LM_DBG("using anonymous identity\n");
		return CSCF_RETURN_TRUE;
	}

    return CSCF_RETURN_FALSE;
}

static int w_emergency_flag(struct sip_msg *msg,char *str1,char *str2) {
	return 1;
}

static int w_380_em_alternative_serv(struct sip_msg * msg, char* str1, char* str2) {
	return 1;
}

static int w_emergency_serv_enabled(struct sip_msg *msg,char *str1,char*str2) {
	return 1;
}

static int w_is_emergency_ruri(struct sip_msg *msg, char *str1, char *str2) {
	int sos;

	str ruri = {msg->first_line.u.request.uri.s,
				msg->first_line.u.request.uri.len};

	LM_DBG("checking if the ruri %.*s is an emergency ruri\n", ruri.len, ruri.s);	

	sos = is_emerg_ruri(ruri, NULL);

	switch(sos){
		case NOT_URN:	
		case NOT_EM_URN: 
			return CSCF_RETURN_ERROR;
		default: 
			return CSCF_RETURN_TRUE;
	}
}

static int w_select_ecscf(struct sip_msg *msg,char *str1,char*str2) {
	return 1;
}

static int w_enforce_sos_routes(struct sip_msg *msg,char *str1,char*str2) {
	return 1;
}

static int w_is_em_registered(struct sip_msg *msg,char *str1,char *str2) {
	return 1;
}

static int w_add_em_path(struct sip_msg * msg, char* str1, char* str2) {
	return 1;
}

static int w_check_em_path(struct sip_msg * msg, char * str1, char * str2) {
	return 1;
}

static int fixup_380_alt_serv(void** param, int param_no){
	char* str1;
	if(param_no!=1){
		LM_ERR("invalid param number");
		return -1;
	}

	str1 = (char*) *param;
	if(!str1 || str1[0] == '\0'){
		LM_ERR("NULL reason");
		return -1;
	}
	return 0;
}
