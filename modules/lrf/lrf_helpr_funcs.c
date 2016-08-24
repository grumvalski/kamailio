/**                                                                                                                                  
   * Returns the corresponding request for a reply, using tm transactions.                                                             
   * @param reply - the reply to find request for                                                                                      
   * @returns the transactional request                                                                                                
   */                                                                                                                                  

#include "../../modules/tm/tm_load.h"

extern struct tm_binds tmb;

struct sip_msg* get_request_from_reply(struct sip_msg *reply)
{                                                                                                                                    
	struct cell *t;                                                                                                                  
	t = tmb.t_gett();                                                                                                                
	if (!t || t==(void*) -1){                                                                                                        
		LM_ERR("Reply without transaction\n");                                          
		return 0;                                                                                                                    
	}                                                                                                                                
	if (t) return t->uas.request;                                                                                                    
		else return 0;                                                                                                                   
}

/**
 * Returns the tm transaction identifiers.
 * If no transaction, then creates one
 * @param msg - the SIP message
 * @param hash - where to write the hash
 * @param label - where to write the label
 * @returns 1 on success and creation of a new transaction, 0 if transaction existed,
 * -1 if failure
 */
int get_transaction(struct sip_msg *msg, unsigned int *hash,unsigned int *label)
{
	if (tmb.t_get_trans_ident(msg,hash,label)<0){   
		LM_DBG("SIP message without transaction. OK - first request\n");
		if (tmb.t_newtran(msg)<0) 
			LM_ERR("Failed creating SIP transaction\n");
		if (tmb.t_get_trans_ident(msg,hash,label)<0){
			LM_ERR("SIP message still without transaction\n");
			return -1;
		} else {
			LM_DBG("New SIP message transaction %u %u\n", *hash,*label);
			return 1;
		}
	} else {
		LM_DBG("Transaction %u %u exists. Retransmission?\n",*hash,*label);
		return 0;
	}
}

/**
 * Transactional SIP response - tries to create a transaction if none found.
 * @param msg - message to reply to
 * @param code - the Status-code for the response
 * @param text - the Reason-Phrase for the response
 * @returns the tmb.t_repy() result
 */
int cscf_reply_transactional(struct sip_msg *msg, int code, char *text)
{
	unsigned int hash,label;
	if (tmb.t_get_trans_ident(msg,&hash,&label)<0){
		if (tmb.t_newtran(msg)<0)
			LM_ERR("Failed creating SIP transaction\n");
	}
	return tmb.t_reply(msg,code,text);
}
