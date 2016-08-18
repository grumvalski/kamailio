/*
 * Copyright (C) 2008-2009 FhG Fokus
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
 *     info@open-ims.org
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
 * emergency-CSCF - SER module interface
 * 
 * Scope:
 *	interface with the lost_client library 
 *  \author Ancuta Onofrei andreea dot ancuta dot onofrei -at- fokus dot fraunhofer dot de
 * 
 */
 

#include "mod.h"

#include "../../ut.h"
#include "../../sr_module.h"
#include "../../locking.h"
#include "../../data_lump.h"
#include "../../modules/tm/tm_load.h"
#include "../../modules/tm/h_table.h"
#include "../../modules/tm/t_reply.h"
#include "../../parser/parse_geoloc.h"

//#include "../../modules/dialog/dlg_mod.h"
#include "../../lib/lost/client.h"
#include "../../lib/lost/parsing.h"
#include "../../lib/lost/pidf_loc.h"
#include "../../lib/ims/ims_getters.h"

#include "dlg_state.h"
#include "lrf.h"
#include "route.h"
#include "multipart_parse.h"

extern struct tm_binds tmb;   
extern str ecscf_name_str;	
extern str lrf_sip_uri_str;
extern int use_default_psap;
extern str default_psap_uri_str;
extern enum user_id_type user_id;

static str options_method     = {"OPTIONS",7};
static str accept_hdr 		  = {"Accept: application/route+xml\r\n",31};
static str no_content_len_hdr = {"Content-Length: 0\r\n",19};
static str content_len_hdr_s  =	{"Content-Length: ",16};
static str content_len_hdr_e  = {"\r\n",2};
static str max_fwds_hdr 	  = {"Max-Forwards: 10\r\n",18};
static str contact_s 		  = {"Contact: <",10};
static str contact_e 		  = {">\r\n",3};
static str route_s 			  = {"Route: <",8};
static str route_e 			  = {">\r\n",3};
static str service_hdr_s 	  = {"Service: ", 9};
static str service_hdr_e 	  = {"\r\n", 2};
static str content_type_hdr   = {"Content-Type: application/pidf+xml\r\n",36};
static str esqk_hdr_name 	  = {"ESQK",4};
static str psap_uri_hdr_name  = {"PSAP-URI",8};

extern int (*sl_reply)(struct sip_msg* _msg, char* _str1, char* _str2); 



/* delete the header ESQK if present in the INVITE reply
 * @param inv_repl - the INVITE reply 
 * @param str1 - not used
 * @param str2 - not used
 * @returns CSCF_RETURN_TRUE if ok, otherwise CSCF_RETURN_FALSE
 */
int E_del_ESQK_info(struct sip_msg * inv_repl, char* str1, char* str2){

	struct hdr_field* esqk_header;

	if((esqk_header = cscf_get_header(inv_repl, esqk_hdr_name))){
		LM_DBG("removing the header ESQK with the value %.*s\n",
				esqk_header->body.len, esqk_header->body.s);
		if(cscf_del_header(inv_repl, esqk_header)==0)
			return CSCF_RETURN_FALSE;
	}

	return CSCF_RETURN_TRUE;

}

int add_loc_info_body_part(struct sip_msg * msg, str loc_info);
int E_add_loc_info(e_dialog * d, struct sip_msg * inv_req, struct sip_msg* opt_repl){
	
	str pidf_body = {NULL, 0};
	int ret;

	LM_DBG("trying to add the location information from the LRF, if present\n");
	
	ret = get_pidf_lo_body(opt_repl, &pidf_body);
	if(ret == -1){
		LM_ERR("could not get the pidf+xml body from the LRF response\n");
		return CSCF_RETURN_FALSE;
	}else if (ret == 1)
		return CSCF_RETURN_TRUE;

	if(add_loc_info_body_part(inv_req, pidf_body)!=0)
		return CSCF_RETURN_FALSE;
	return CSCF_RETURN_TRUE;
}

/* set a value for the PSAP
 * @param d - the dialog to be used
 * @param psap_uri - the psap uri to be set
 */
int E_set_psap(e_dialog * d, str psap_uri){

	if(!psap_uri.s || !psap_uri.len){
		LM_ERR("empty PSAP-URI header in the OPTIONS reply \n");
		goto error;
	}

	STR_SHM_DUP(d->psap_uri, psap_uri, "E_set_psap");
	return CSCF_RETURN_TRUE;
error:
out_of_memory:
	return CSCF_RETURN_FALSE;
}

int E_set_em_info(e_dialog * d, struct sip_msg * opt_repl){

	struct hdr_field* esqk_header = NULL;
	struct hdr_field* psap_uri_hdr = NULL;
	
	if(d->anonymous)
		goto psap_set;

	if(!(esqk_header = cscf_get_header(opt_repl, esqk_hdr_name))){
		LM_ERR("could not found the header %.*s in the OPTIONS reply\n", 
				esqk_hdr_name.len, esqk_hdr_name.s);
		goto error;
	}
	if(!esqk_header->body.s || !esqk_header->body.len){
		LM_ERR("empty Esqk header\n");
		goto error;
	}
	STR_SHM_DUP(d->esqk, esqk_header->body, "E_set_em_info");

psap_set:	
	if(!(psap_uri_hdr = cscf_get_header(opt_repl, psap_uri_hdr_name))){
		LM_ERR("could not found the header %.*s in the OPTIONS reply\n", 
				psap_uri_hdr_name.len, psap_uri_hdr_name.s);
		goto error;
	}
	
	if(E_set_psap(d, psap_uri_hdr->body) == CSCF_RETURN_FALSE)
		goto error;


	LM_DBG("psap_uri is %.*s and esqk value is %.*s\n",
			d->psap_uri.len, d->psap_uri.s, d->esqk.len, d->esqk.s);

	return CSCF_RETURN_TRUE;
error:
out_of_memory:
	if(d->esqk.s){
		shm_free(d->esqk.s);
		d->esqk.s = NULL;
	}
	return CSCF_RETURN_FALSE;
}


/* take actions according to the response code of the OPTIONS reply from the LRF
 * @param opt_repl - the OPTIONS reply
 * @param inv_trans - the INVITE transaction
 * @param code - the code of the response 
 * @returns -1 in case of error, 0 for okloose_route();
	E_query_LRF("orig");

 */
int E_process_options_repl(struct sip_msg * opt_repl, struct cell * inv_trans, int code){

	int ret;
	ret = -1;
	e_dialog * d = NULL;
	str call_id;

	if(code<200)
		return 0;

	if(!inv_trans->uas.request){
		LM_ERR("INVITE message is not set in the INVITE trans\n");
		goto error;
	}
	
	enum e_dialog_direction dir = get_dialog_direction("orig");
		
	call_id = cscf_get_call_id(inv_trans->uas.request,0);
	if (!call_id.len)
		goto error;

	LM_DBG("Call-ID <%.*s>\n",call_id.len,call_id.s);

	d = is_e_dialog_dir(inv_trans->uas.request, call_id,dir);
	if(!d){
		LM_ERR("message did not create a dialog\n");
		goto error;
	}
	
	if(d->is_cancelled){
		LM_DBG("the emergency call was cancelled, no further processing\n");
		goto end;
	}

	if(code >= 300){
		//send error response to INVITE and update the dialog
		LM_DBG("received an error response %i\n", code);

		if(code != 408 && use_default_psap){
			if(E_set_psap(d, default_psap_uri_str) != CSCF_RETURN_TRUE)
				goto error;
			
			LM_DBG("trying to use the defautl PSAP\n");
			goto fwd_invite;
		}

		if(tmb.t_reply(inv_trans->uas.request, 404, ECSCF_NO_PSAP)<0){
			LM_ERR("Could not reply to the INVITE request\n");
			goto error;
		}
		LM_DBG("sent a 404 no available PSAP error response\n");

		d->state = DLG_STATE_TERMINATED;
		d->expires = 0;
		d->lr_session_expires = 0;

		d_unlock(d->hash);				
		LM_DBG("setting the dialog t0 expire interval\n");
		print_e_dialogs(L_INFO);

	}else{
		if(E_set_em_info(d, opt_repl) != CSCF_RETURN_TRUE)
			goto error;

		if(!d->anonymous && E_add_esqk(inv_trans->uas.request, d->esqk) != CSCF_RETURN_TRUE)
			goto error;

fwd_invite:
		if(!d->location && E_add_loc_info(d, inv_trans->uas.request, opt_repl) != CSCF_RETURN_TRUE)
			goto error;
		
		if(E_fwd_to_psap(inv_trans->uas.request, d->psap_uri) != CSCF_RETURN_TRUE)
			goto error;

		if(E_add_record_route(inv_trans->uas.request, 0, 0) != CSCF_RETURN_TRUE)
			goto error;

		if(tmb.t_relay(inv_trans->uas.request, 0, 0) != 1){
			LM_ERR("Could not relay the INVITE request\n");
			goto error;
		}
		d->forwarded  = 1;
		cscf_del_nonshm_lumps(inv_trans->uas.request);
		LM_ERR("forward the INVITE request\n");
	}
end:	
	ret = 0;	
error:
	if(d)	d_unlock(d->hash);
	cscf_del_nonshm_lumps(inv_trans->uas.request);
	return ret;

}
#define FParam_INT(val) { \
	 .v = { \
		.i = val \
	 },\
	.type = FPARAM_INT, \
	.orig = "int_value", \
};

#define FParam_STRING(val) { \
	.v = { \
		.str = STR_STATIC_INIT(val) \
	},\
	.type = FPARAM_STR, \
	.orig = val, \
};


/* callback function for the OPTIONS reply
 * @param t - OPTIONS transaction
 * @param type 
 * @param ps - shm stored parameters of the callback
 */
void options_resp_cb(struct cell* t, int type, struct tmcb_params* ps){

	struct initial_tr * cb_par;
	struct cell* inv_trans;

	LM_DBG("received an %i answer for trans %p, req %p, repl %p\n",	ps->code, t, ps->req, ps->rpl);

	cb_par = *((struct initial_tr **)ps->param);
	
	LM_DBG("cb_par:%p index: %u label: %u callid: %.*s\n", 
			cb_par, cb_par->hash_index, cb_par->label, cb_par->callid.len, cb_par->callid.s);

	if (tmb.t_lookup_ident(&inv_trans, cb_par->hash_index, cb_par->label) < 0) {                                                                                                                                                                                                                      
		LM_ERR("transaction not found %d:%d\n", cb_par->hash_index, cb_par->label);                                                                   
		goto error;
	}

	if(E_process_options_repl(ps->rpl, inv_trans, ps->code)<0){
		LM_ERR("Could not process the OPTIONS response\n");
		tmb.t_reply(inv_trans->uas.request, 500, ECSCF_INTERNAL_ERROR);
	}

	//set the OPTIONS trans as the current one
	tmb.t_sett(t, T_BR_UNDEFINED);

error:
	//clean the callback parameters 
	shm_free(cb_par);
	ps->param = NULL;
	return;
}

/**
 * Send an OPTIONS to lrf
 * @returns 0 if OK, -1 if failure
 */
int send_options_req(str req_uri, str location, str service, struct initial_tr * inv_tr){

	str h={0,0};
	struct initial_tr * cb_par;
	int content_len;
	str content_len_str;
	uac_req_t uac_r;
	
	LM_DBG("sending OPTIONS to <%.*s>, service %.*s\n",
		req_uri.len, req_uri.s, service.len, service.s);

	if(!inv_tr){
		LM_ERR("invalid initial trans argument\n");
		return -1;
	}

	if(!req_uri.len || req_uri.s[0] == '\0'){
		LM_ERR("invalid req_uri argument\n");
		return -1;
	}

	content_len = location.len;
	content_len_str.s = int2str((unsigned int) content_len, &content_len_str.len);
	if(content_len_str.len <0 || content_len_str.len > (INT2STR_MAX_LEN)){
		LM_ERR("could not encode the content length, %i\n", content_len);
		return -1;
	}

	h.len = accept_hdr.len+max_fwds_hdr.len;
	h.len += contact_s.len + ecscf_name_str.len + contact_e.len;

	h.len += route_s.len + lrf_sip_uri_str.len + route_e.len;
	h.len += service_hdr_s.len + service.len + service_hdr_e.len;

	if(!location.len || !location.s)
		h.len +=no_content_len_hdr.len;
	else{
		h.len +=content_len_hdr_s.len + content_len_str.len + content_len_hdr_e.len;
		h.len +=content_type_hdr.len;
	}

	h.s = pkg_malloc(h.len);
	if (!h.s){
		LM_ERR("Error allocating %d bytes\n",h.len);
		h.len = 0;
		return 0;
	}

	char * p = (char*)shm_malloc(sizeof(struct initial_tr)+sizeof(char)*inv_tr->callid.len);
	if(!p){
		LM_ERR("Error allocating cb_par: %d bytes\n",
				(int)(sizeof(struct initial_tr)+sizeof(char)*inv_tr->callid.len));
		goto error;
	}
	cb_par = (struct initial_tr *)p;
	cb_par->hash_index = inv_tr->hash_index;
	cb_par->label = inv_tr->label;
	cb_par->callid.len = inv_tr->callid.len;
	cb_par->callid.s = (char*)(p+sizeof(struct initial_tr));
	memcpy(cb_par->callid.s, inv_tr->callid.s, inv_tr->callid.len*sizeof(char));
	
	h.len = 0;
	STR_APPEND(h,accept_hdr);
	
	STR_APPEND(h,service_hdr_s);
	STR_APPEND(h,service);
	STR_APPEND(h,service_hdr_e);

	STR_APPEND(h,max_fwds_hdr);

	STR_APPEND(h,contact_s);
	STR_APPEND(h,ecscf_name_str);
	STR_APPEND(h,contact_e);

	STR_APPEND(h,route_s);
	STR_APPEND(h,lrf_sip_uri_str);
	STR_APPEND(h,route_e);

	if(!location.len || !location.s){
		STR_APPEND(h,no_content_len_hdr);
	}else{
		STR_APPEND(h,content_type_hdr);
		STR_APPEND(h,content_len_hdr_s);
		STR_APPEND(h,content_len_str);
		STR_APPEND(h,content_len_hdr_e);
	}

	LM_DBG("headers are: \n%.*s, cb_par:%p index: %u label: %u\n", 
			h.len, h.s, cb_par, cb_par->hash_index, cb_par->label);

	set_uac_req(&uac_r, &options_method, &h, &location, 0, TMCB_LOCAL_COMPLETED, options_resp_cb, (void*)cb_par);
	if (tmb.t_request(&uac_r, &req_uri, &lrf_sip_uri_str, &ecscf_name_str, &lrf_sip_uri_str) < 0) {
                LM_ERR("Error sending in transaction\n");
                goto error;
    }
	
	if (h.s) pkg_free(h.s);
	return 1;

error:
	if (h.s) pkg_free(h.s);
	return 0;
}

static str anonym_user = {"sip:anonymous@domain.org", 24};

/* Find the appropriate psap uri that the request should be forwarded to, by querying the LRF
 * @param msg - the sip request
 * @param str1 
 * @param str2 
 * @returns #CSCF_RETURN_TRUE if ok, #CSCF_RETURN_FALSE if not or #CSCF_RETURN_BREAK on error 
 */
int E_query_LRF(struct sip_msg* msg, char* direction, char* str2){

	e_dialog* d;
	str call_id, from_uri;
	str location_str = {0, 0};
	str service, req_uri = {0,0};
	struct initial_tr inv_tr;
	struct cell     *t;
	
	enum e_dialog_direction dir = get_dialog_direction(direction);
	if(dir == DLG_MOBILE_UNKNOWN){
		LM_ERR("error invalid argument str1\n");
		return CSCF_RETURN_FALSE;
	}
		
	call_id = cscf_get_call_id(msg,0);
	if (!call_id.len){
		LM_ERR("no or invalid Call-ID header\n");
		return CSCF_RETURN_FALSE;
	}
	
	LM_DBG("Call-ID <%.*s>\n",call_id.len,call_id.s);

	if(cscf_get_from_uri(msg, &from_uri)==0){
		LM_ERR("no or invalid From header\n");
		return CSCF_RETURN_FALSE;
	}

	d = is_e_dialog_dir(msg, call_id,dir);
	if(!d){
		LM_ERR("message did not create no dialog\n");
		return CSCF_RETURN_ERROR;
	}

	if(d->anonymous){
		req_uri.s = anonym_user.s;
		req_uri.len = anonym_user.len;
	}else if(user_id==CONTACT_ADDR_ID){

		req_uri = cscf_get_contact(msg);
		if(req_uri.s == NULL || req_uri.len == 0){
			LM_ERR("no or invalid Contact header\n");
			return CSCF_RETURN_FALSE;
		}

	}else if(user_id==SIP_URI_ID){

		if(cscf_get_from_uri(msg, &req_uri)!=1){
			LM_ERR("no or invalid From header\n");
			return CSCF_RETURN_FALSE;
		}
		
		if(req_uri.s == NULL || req_uri.len == 0){
			LM_ERR("no or invalid Contact header\n");
			return CSCF_RETURN_FALSE;
		}
	}else{
		LM_ERR("invalid user id type\n");
		return CSCF_RETURN_FALSE;
	}

	if(d->location_str.len && d->location_str.s){
		LM_DBG("the message contained supported location information\n");
		location_str.s = d->location_str.s;
		location_str.len = d->location_str.len;
	}else{
		LM_DBG("the message did not contain supported location information\n");
	}

	t = tmb.t_gett();
	if (!t || t == T_UNDEFINED) {
        LM_ERR("could not retrive  label of the current message's transaction\n");
        goto ret_false;
    }

	inv_tr.hash_index = t->hash_index; 
	inv_tr.label = t->label; 
	inv_tr.callid.len = msg->callid->len; 
	inv_tr.callid.s = msg->callid->name.s; 
	
	service = msg->first_line.u.request.uri;

	if(!send_options_req(req_uri, location_str, service, &inv_tr)){
		goto ret_false;
	}
	
	d_unlock(d->hash);
	return CSCF_RETURN_TRUE;

ret_false:
	d_unlock(d->hash);
	return CSCF_RETURN_FALSE;
}

/* Parse the location information by value from the INVITE request
 * TODO: if the location information is by reference, or there is no location information
 * store the location information in the dialog
 * @param msg - the SIP request
 * @param str1 - not used
 * @param str2 - not used
 * @returns #CSCF_RETURN_TRUE if ok (no Geolocation found or msg successfully parsed), #CSCF_RETURN_FALSE if no location-conveyance info is found or #CSCF_RETURN_ERROR on error 
 */
int E_get_location(struct sip_msg* msg, char* str1, char * str2){
	
	e_dialog * d;
	loc_fmt crt_loc_fmt;
	str pidf_body={NULL, 0};
	xmlNode * presence, * loc;
	struct loc_value *value;
	int ret;
	str call_id;

	loc = NULL;

	enum e_dialog_direction dir = get_dialog_direction(str1);
	if(dir == DLG_MOBILE_UNKNOWN){
		LM_ERR("error invalid argument %s\n", str1);
		return CSCF_RETURN_ERROR;
	}
		
	call_id = cscf_get_call_id(msg,0);
	if (!call_id.len)
		return CSCF_RETURN_ERROR;

	LM_DBG("Call-ID <%.*s>\n",call_id.len,call_id.s);

	d = is_e_dialog_dir(msg, call_id,dir);
	if(!d){
		LM_ERR("message did not create a dialog\n");
		return CSCF_RETURN_ERROR;
	}

	ret = parse_geoloc(msg);
	switch(ret){
		case -1:
			LM_ERR("error while parsing the Geolocation header\n");
			goto error_loc;
		case 0: break;
		case 1: 
			LM_ERR("no Geolocation header found => emergency call without location information\n");
			goto no_geoloc;
		default:  	
			LM_ERR("unhandled return value %d\n", ret);
			goto error_loc;
	}

	
	print_geoloc((struct geoloc_body*)msg->geolocation->parsed);
	if(!((struct geoloc_body*)msg->geolocation)->retrans_par){
		LM_ERR("the location does not support routing based on location\n");
		goto error_loc;
	}

	for(value = ((struct geoloc_body*)msg->geolocation->parsed)->loc_list;value!=NULL; value=value->next){
	
		if(value->locURI.type != CID_T){
			LM_ERR("geolocation uri type unsupported\n");
			goto error_loc;
		}
	}

	
	if(get_pidf_lo_body(msg, &pidf_body)){
		LM_ERR("could not get the pidf+xml body, but with the Geolocation header set\n");
		goto error_loc;
	}
	
	//LM_DBG("the pidf body to be parsed is %.*s\n",
	//		pidf_body.len, pidf_body.s);

	if(!(presence = xml_parse_string(pidf_body))){
		LM_ERR("invalid xml content\n");
		goto error_loc;
	}

	//print_element_names(presence);

	if(!(loc = has_loc_info(&ret, presence, &crt_loc_fmt))){
	
		LM_ERR("could not find a valid location element, but with the Geolocation header set\n");
		xmlFreeDoc(presence->doc);
		goto error_loc;
	}

	if((crt_loc_fmt == GEO_SHAPE_LOC) || (crt_loc_fmt == NEW_CIV_LOC) ||
			(crt_loc_fmt == OLD_CIV_LOC) || (crt_loc_fmt == GEO_COORD_LOC)){
	
		LM_DBG("LoST supported format, setting the location\n");

	}else if(crt_loc_fmt == ERR_LOC){
		LM_ERR("error while parsing the location information\n");
		xmlFreeDoc(presence->doc);
		goto error_loc;
	}else{
		LM_DBG("no LoST supported format\n");
		xmlFreeDoc(presence->doc);
		goto error_loc;
	}
//	LM_DBG("printing the location useful tree\n");
//	print_element_names(loc);

	d->location = loc;
	d->location_str.s = pidf_body.s;
	d->location_str.len = pidf_body.len;
	d->d_loc_fmt = crt_loc_fmt;
no_geoloc:
	d_unlock(d->hash);
	return CSCF_RETURN_TRUE;
	
error_loc:
	d_unlock(d->hash);
	return CSCF_RETURN_FALSE;
}


