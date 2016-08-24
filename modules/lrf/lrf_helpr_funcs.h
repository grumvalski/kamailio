
#ifndef _LRF_HLPR_FUNCS_H
#define  _LRF_HLPR_FUNCS_H

struct sip_msg* get_request_from_reply(struct sip_msg *reply);
int get_transaction(struct sip_msg *msg, unsigned int *hash,unsigned int *label);
int cscf_reply_transactional(struct sip_msg *msg, int code, char *text);

#endif

