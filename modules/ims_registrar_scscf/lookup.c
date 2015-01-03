/*
 * $Id$
 *
 * Lookup contacts in usrloc
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * History:
 * ---------
 * 2003-03-12 added support for zombie state (nils)
 */
/*!
 * \file
 * \brief SIP registrar module - lookup contacts in usrloc
 * \ingroup registrar
 */


#include <string.h>
#include "../../ut.h"
#include "../../dset.h"
#include "../../str.h"
#include "../../config.h"
#include "../../action.h"
#include "../../parser/parse_rr.h"
#include "../ims_usrloc_scscf/usrloc.h"
#include "../../lib/ims/ims_getters.h"
#include "common.h"
#include "regtime.h"
#include "reg_mod.h"
#include "lookup.h"
#include "config.h"

#include "save.h"

#define allowed_method(_msg, _c) \
	( !method_filtering || ((_msg)->REQ_METHOD)&((_c)->methods) )

/*! \brief
 * Lookup contact in the database and rewrite Request-URI
 * \return: -1 : not found
 *          -2 : found but method not allowed
 *          -3 : error
 */
int lookup(struct sip_msg* _m, udomain_t* _d) {
    impurecord_t* r;
    str aor, uri;
    ucontact_t* ptr;
    int res;
    int ret;
    str path_dst;
    flag_t old_bflags;
    int i = 0;


    if (_m->new_uri.s) uri = _m->new_uri;
    else uri = _m->first_line.u.request.uri;

    if (extract_aor(&uri, &aor) < 0) {
	LM_ERR("failed to extract address of record\n");
	return -3;
    }

    get_act_time();

    ul.lock_udomain(_d, &aor);
    res = ul.get_impurecord(_d, &aor, &r);
    if (res > 0) {
	LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
	ul.unlock_udomain(_d, &aor);
	return -1;
    }
    ret = -1;

    while (i < MAX_CONTACTS_PER_IMPU && (ptr = r->newcontacts[i])) {
	if (VALID_CONTACT(ptr, act_time) && allowed_method(_m, ptr)) {
	    LM_DBG("Found a valid contact [%.*s]\n", ptr->c.len, ptr->c.s);
	    i++;
	    break;
	}
	i++;
    }

    /* look first for an un-expired and suported contact */
    if (ptr == 0) {
	/* nothing found */
	goto done;
    }

    ret = 1;
    if (ptr) {
	if (rewrite_uri(_m, &ptr->c) < 0) {
	    LM_ERR("unable to rewrite Request-URI\n");
	    ret = -3;
	    goto done;
	}

	/* reset next hop address */
	reset_dst_uri(_m);

	/* If a Path is present, use first path-uri in favour of
	 * received-uri because in that case the last hop towards the uac
	 * has to handle NAT. - agranig */
	if (ptr->path.s && ptr->path.len) {
	    if (get_path_dst_uri(&ptr->path, &path_dst) < 0) {
		LM_ERR("failed to get dst_uri for Path\n");
		ret = -3;
		goto done;
	    }
	    if (set_dst_uri(_m, &path_dst) < 0) {
		LM_ERR("failed to set dst_uri of Path\n");
		ret = -3;
		goto done;
	    }
	} else if (ptr->received.s && ptr->received.len) {
	    if (set_dst_uri(_m, &ptr->received) < 0) {
		ret = -3;
		goto done;
	    }
	}

	set_ruri_q(ptr->q);

	old_bflags = 0;
	getbflagsval(0, &old_bflags);
	setbflagsval(0, old_bflags | ptr->cflags);

	if (ptr->sock)
	    set_force_socket(_m, ptr->sock);

	ptr = ptr->next;
    }

    /* Append branches if enabled */
    if (!cfg_get(registrar, registrar_cfg, append_branches)) goto done;

    //the last i was the first valid contact we found - let's go through the rest of valid contacts and append the branches.
    while (i < MAX_CONTACTS_PER_IMPU && (ptr = r->newcontacts[i])) {
	if (VALID_CONTACT(ptr, act_time) && allowed_method(_m, ptr)) {
	    path_dst.len = 0;
	    if (ptr->path.s && ptr->path.len
		    && get_path_dst_uri(&ptr->path, &path_dst) < 0) {
		LM_ERR("failed to get dst_uri for Path\n");
		continue;
	    }

	    /* The same as for the first contact applies for branches
	     * regarding path vs. received. */
	    if (km_append_branch(_m, &ptr->c, path_dst.len ? &path_dst : &ptr->received,
		    &ptr->path, ptr->q, ptr->cflags, ptr->sock) == -1) {
		LM_ERR("failed to append a branch\n");
		/* Also give a chance to the next branches*/
		continue;
	    }
	}
	i++;
    }

done:
    ul.unlock_udomain(_d, &aor);
    return ret;
}

/*! \brief the impu_registered() function
 * Return true if the AOR in the To Header is registered
 */
int impu_registered(struct sip_msg* _m, char* _t, char* _s)
{
	impurecord_t* r;
	int res, ret=-1;

	str impu;
	impu = cscf_get_public_identity(_m);

	LM_DBG("Looking for IMPU <%.*s>\n", impu.len, impu.s);

	ul.lock_udomain((udomain_t*)_t, &impu);
	res = ul.get_impurecord((udomain_t*)_t, &impu, &r);

	if (res < 0) {
		ul.unlock_udomain((udomain_t*)_t, &impu);
		LM_ERR("failed to query usrloc for IMPU <%.*s>\n", impu.len, impu.s);
		return ret;
	}

	if (res == 0) {
		if (r->reg_state == IMPU_REGISTERED ) ret = 1;
		ul.unlock_udomain((udomain_t*) _t, &impu);
		LM_DBG("'%.*s' found in usrloc\n", impu.len, ZSW(impu.s));
		return ret;
	}

	ul.unlock_udomain((udomain_t*)_t, &impu);
	LM_DBG("'%.*s' not found in usrloc\n", impu.len, ZSW(impu.s));
	return ret;
}

/*! \brief the term_impu_registered() function
 * Return true if the AOR in the Request-URI  for the terminating user is registered
 */
int term_impu_registered(struct sip_msg* _m, char* _t, char* _s)
{
	//str uri, aor;
	struct sip_msg *req;	
	int i;
	str uri;
	impurecord_t* r;
	int res;

//	if (_m->new_uri.s) uri = _m->new_uri;
//	else uri = _m->first_line.u.request.uri;
//
//	if (extract_aor(&uri, &aor) < 0) {
//		LM_ERR("failed to extract address of record\n");
//		return -1;
//	}
	
	req = _m;	
	if (!req){
		LM_ERR(":term_impu_registered: NULL message!!!\n");
		return -1;
	}
 	if (req->first_line.type!=SIP_REQUEST){
 		req = get_request_from_reply(req);
 	}
	
	if (_m->new_uri.s) uri = _m->new_uri;
	else uri = _m->first_line.u.request.uri;
		
	for(i=0;i<uri.len;i++)
		if (uri.s[i]==';' || uri.s[i]=='?') {
			uri.len = i;
			break;
		}
	
	LM_DBG("term_impu_registered: Looking for <%.*s>\n",uri.len,uri.s);

	ul.lock_udomain((udomain_t*)_t, &uri);
	res = ul.get_impurecord((udomain_t*)_t, &uri, &r);

	if (res < 0) {
		ul.unlock_udomain((udomain_t*)_t, &uri);
		LM_ERR("failed to query for terminating IMPU <%.*s>\n", uri.len, uri.s);
		return -1;
	}

	if (res == 0) {
		//ul.release_impurecord(r);
		ul.unlock_udomain((udomain_t*) _t, &uri);
		LM_DBG("'%.*s' found in usrloc\n", uri.len, ZSW(uri.s));
		return 1;
	}

	ul.unlock_udomain((udomain_t*)_t, &uri);
	LM_DBG("'%.*s' not found in usrloc\n", uri.len, ZSW(uri.s));
	return -1;
}

int scscf_fetch_impus(struct sip_msg* _m, udomain_t* _d, str* _i, str* dest) {
    int i, j, res;
    str aor;
    impurecord_t* impu_rec;
    ims_public_identity* impi;

    pv_spec_t avp_spec;
    int_str avp_val;
    int_str avp_name;
    unsigned short avp_type;

	LM_DBG("Fetching IMPUs for '%.*s'\n", _i->len, _i->s);

    if (dest->s && dest->len > 0) {
        if (pv_parse_spec(dest, &avp_spec)==0 || avp_spec.type!=PVT_AVP) {
            LM_ERR("malformed or non AVP %.*s AVP definition\n", dest->len, dest->s);
            return -1;
        }

        if(pv_get_avp_name(0, &(avp_spec.pvp), &avp_name, &avp_type)!=0) {
            LM_ERR("[%.*s]- invalid AVP definition\n", dest->len, dest->s);
            return -1;
        }
    } else {
	    LM_ERR("no AVP provided\n");
	    return -1;
    }
    if (extract_aor(_i, &aor) < 0) {
	    LM_ERR("failed to extract address of record\n");
	    return -1;
    }

    ul.lock_udomain(_d, &aor);

    res = ul.get_impurecord(_d, &aor, &impu_rec);
    if (res > 0) {
	    LM_DBG("'%.*s' Not found in usrloc\n", aor.len, ZSW(aor.s));
	    ul.unlock_udomain(_d, &aor);
	    return -1;
    }

    if (!impu_rec->s) {
        LM_DBG("no subscription associated with impu\n");
	    ul.unlock_udomain(_d, &aor);
        return -1;
    }
    //get IMPU set from the presentity's subscription
    lock_get(impu_rec->s->lock);
    for (i = 0; i < impu_rec->s->service_profiles_cnt; i++) {
	    for (j = 0; j < impu_rec->s->service_profiles[i].public_identities_cnt; j++) {
	        impi = &(impu_rec->s->service_profiles[i].public_identities[j]);
	        if (impi->barring != 0) {
                continue;
            }
            if (impi->public_identity.s && impi->public_identity.len > 0) {
                avp_val.s = impi->public_identity;
                if(add_avp(AVP_VAL_STR|avp_type, avp_name, avp_val)!=0) {
	                LM_ERR("failed to add %.*s\n to IMPUs AVP\n",
                            impi->public_identity.len, impi->public_identity.s);
                    lock_release(impu_rec->s->lock);
	                ul.unlock_udomain(_d, &aor);
                    return -1;
                }
				LM_DBG("added %.*s\n to IMPUs AVP\n",
						impi->public_identity.len, impi->public_identity.s);
            }
        }
    }

    lock_release(impu_rec->s->lock);
    ul.unlock_udomain(_d, &aor);

    return 1;
}
