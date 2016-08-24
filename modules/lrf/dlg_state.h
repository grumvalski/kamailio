/**
 * $Id: dlg_state.h 708 2009-04-23 15:31:52Z aon $
 *  
 * Copyright (C) 2009 FhG Fokus
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
 */
 
/**
 * \file
 * 
 * LRF - Dialog State
 * 
 *  \author Andreea Ancuta Onofrei andreea.ancuta.onofrei-at-fokus.fraunhofer.de
 *   
 */
 

#ifndef LRF_DLG_STATE_H
#define LRF_DLG_STATE_H

#include "../../sr_module.h"
#include "mod.h"
#include "../../locking.h"
#include "../../modules/tm/dlg.h"
#include "../../modules/tm/tm_load.h"

enum lrf_dialog_method {
	DLG_METHOD_OTHER=0,
	DLG_METHOD_INVITE=1,
	DLG_METHOD_SUBSCRIBE=2	
};

/** The last dialog type */
#define DLG_METHOD_MAX DLG_METHOD_SUBSCRIBE

enum lrf_dialog_state {
	DLG_STATE_UNKNOWN=0,
	DLG_STATE_INITIAL=1,
	DLG_STATE_EARLY=2,
	DLG_STATE_CONFIRMED=3,
	DLG_STATE_TERMINATED_ONE_SIDE=4,
	DLG_STATE_TERMINATED=5	
};

enum lrf_dialog_direction {
	DLG_MOBILE_ORIGINATING=0,
	DLG_MOBILE_TERMINATING=1,
	DLG_MOBILE_UNKNOWN=2
};

typedef struct _lrf_dialog {
	unsigned int hash;
	str call_id;
	str target_uri;
	enum lrf_dialog_direction direction; 
	
	enum lrf_dialog_method method;
	str method_str;
	int first_cseq;
	int last_cseq;
	enum lrf_dialog_state state;
	time_t expires;
	time_t lr_session_expires;  		/**< last remember request - session-expires header			*/
	str refresher;						/**< session refresher				*/
	unsigned char uac_supp_timer; 		/** < requester uac supports timer */
	
	unsigned char is_releasing;			/**< weather this dialog is already being 
	  										released or not, or its peer, with count on 
											tries 										*/	
	str *routes;
	unsigned short routes_cnt;

	dlg_t *dialog_s;  /* dialog as UAS*/
	dlg_t *dialog_c;  /* dialog as UAC*/
			
	struct _lrf_dialog *next,*prev;	
} lrf_dialog;

typedef struct {
	lrf_dialog *head,*tail;
	gen_lock_t *lock;				/**< slot lock 					*/	
} lrf_dialog_hash_slot;


/**
 * Computes the hash for a string.
 * @param call_id - input string
 * @returns - the hash
 */
static inline unsigned int get_lrf_dialog_hash(str call_id, int size)
{
	if (call_id.len==0) return 0;
#define h_inc h+=v^(v>>3)
   char* p;
   register unsigned v;
   register unsigned h;

   h=0;
   for (p=call_id.s; p<=(call_id.s+call_id.len-4); p+=4){
       v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
       h_inc;
   }
   v=0;
   for (;p<(call_id.s+call_id.len); p++) {
       v<<=8;
       v+=*p;
   }
   h_inc;

   h=((h)+(h>>11))+((h>>13)+(h>>23));
   return (h)%size;
#undef h_inc 
}


int lrf_dialogs_init(int hash_size);

void lrf_dialogs_destroy();

/**
 * Locks the required part of the hash table.
 * @param hash - hash of the element to lock (hash slot number)
 */
static inline void d_lock(gen_lock_t *lock)
{
	lock_get(lock);
}

/**
 * UnLocks the required part of the hash table.
 * @param hash - hash of the element to lock (hash slot number)
 */
static inline void d_unlock(gen_lock_t *lock)
{
	lock_release(lock);
}


time_t d_time_now;							/**< current time for dialog updates 	*/
/**
 * Actualize the current time.
 * @returns the current time
 */
static inline int d_act_time()
{
	d_time_now=time(0);
	return d_time_now;
}

/**
 * Finds the contact target_uri for a dialog.
 * @param msg - the SIP message to look into
 * @param direction - look for originating or terminating contact ("orig"/"term")
 * @returns 1 if found, 0 if not
 */
static inline int find_dialog_contact(struct sip_msg *msg,enum lrf_dialog_direction dir,str *target_uri)
{
	switch(dir){
		case DLG_MOBILE_ORIGINATING:
			/*if (!cscf_get_originating_contact(msg,host,port,transport))
				return 0;
			return 1;*/
		case DLG_MOBILE_TERMINATING:
			/*if (!cscf_get_terminating_contact(msg))
				return 0;*/
			return 1;
		default:
			LM_ERR("Unknown direction %d",dir);
			return 0;
	}
	return 1;
}


lrf_dialog* new_lrf_dialog(str call_id, str target_URI);
lrf_dialog* add_lrf_dialog(str call_id, str target_URI);
//int is_lrf_dialog(str call_id, str target_URI, enum p_dialog_direction *dir);
int is_lrf_dialog_dir(str call_id,enum lrf_dialog_direction dir);

lrf_dialog* get_lrf_dialog(str call_id, enum lrf_dialog_direction *dir);
lrf_dialog* get_lrf_dialog_dir(str call_id,enum lrf_dialog_direction dir);
lrf_dialog* get_lrf_dialog_dir_nolock(str call_id,enum lrf_dialog_direction dir);
//int terminate_lrf_dialog(lrf_dialog *d);
void del_lrf_dialog(lrf_dialog *d);
void free_lrf_dialog(lrf_dialog *d);
void print_lrf_dialogs(int log_level);
		


int LRF_is_in_dialog(struct sip_msg* msg, char* str1, char* str2);

int LRF_save_dialog(struct sip_msg* msg, char* str1, char* str2);

int LRF_update_dialog(struct sip_msg* msg, char* str1, char* str2);

int LRF_drop_dialog(struct sip_msg* msg, char* str1, char* str2);

void dialog_timer(unsigned int ticks, void* param);
		
#endif
