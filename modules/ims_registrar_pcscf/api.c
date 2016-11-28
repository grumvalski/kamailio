/*
 * Functions that process REGISTER message
 * and store data in usrloc
 *
 * Copyright (C) 2010 Daniel-Constantin Mierla (asipto.com)
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
 */

#include <stdio.h>

#include "../../dprint.h"

#include "reg_mod.h"
#include "service_routes.h"
#include "api.h"

/**
 *
 * table->s must be zero-terminated
 */
pcontact_t* regapi_get_contactp(sip_msg_t *msg, udomain_t *domain, enum pcontact_reg_states reg_state)
{

	return getContactP(msg, domain, reg_state);
}

/**
 *
 */
int bind_registrar(p_registrar_api_t* api)
{
	if (!api) {
		ERR("Invalid parameter value\n");
		return -1;
	}
	api->get_contactp       = regapi_get_contactp;

	return 0;
}
