/**
 * Copyright (C) 2014 Federico Cabiddu (federico.cabiddu@gmail.com)
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
 */


#include <string.h>
#include <stdio.h>
#include "em_numbers.h"
#include "p_em_rpc.h"

extern em_nb_list emerg_nb_list;

static const char* rpc_p_em_dump_doc[2] = {
	"Dump PCSCF Emergency numbers table",
	0
};


static const char* rpc_p_em_reload_doc[2] = {
	"Reload PCSCF Emergency numbers table",
	0
};

/*************************** RPC functions *****************************/

/*!
 * \brief Dump the content of the tsilo table
 * \param rpc RPC node that should be filled
 * \param c RPC void pointer
 */
static void rpc_p_em_dump(rpc_t *rpc, void *c)
{
	void* th;
	void* ah;
	
	em_nb * emerg_number;

	if (rpc->add(c, "{", &th) < 0)
	{
		rpc->fault(c, 500, "Internal error creating top rpc");
		return;
	}

	emerg_number = emerg_nb_list;
	
	while(emerg_number){
		if(rpc->struct_add(th, "{", 
					"ENTRY", &ah) < 0) {
				rpc->fault(c, 500, "Internal error creating entry top struct");
				return;
		}
		
		if(rpc->struct_add(ah, "SSu",
					"NUMBER", &emerg_number->number, 
					"URN", &emerg_number->urn,
					"TYPE", emerg_number->type)<0) {
				rpc->fault(c, 500, "Internal error creating entry struct");
				return;
		}
		
		emerg_number = emerg_number->next;
	}
	
}
/*!
 * \brief Show the transactions for a given R-URI
 * \param rpc RPC node that should be filled
 * \param c RPC void pointer
 */
static void rpc_p_em_reload(rpc_t *rpc, void *c)
{
	clean_em_numbers();

	if (store_em_numbers() < 0) {
		rpc->fault(c, 500, "Reload Failed");
	}
	return;
}

rpc_export_t rpc_methods[] = {
	{ "pcscf_emergency.dump",	rpc_p_em_dump,		rpc_p_em_dump_doc,		0 },
	{ "pcscf_emergency.reload",	rpc_p_em_reload,	rpc_p_em_reload_doc,	0 },
    { 0, 0, 0, 0}
};

