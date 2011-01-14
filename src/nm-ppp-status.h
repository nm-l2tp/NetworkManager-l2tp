/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-l2tp-service - L2TP VPN integration with NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_PPP_STATUS_H
#define NM_PPP_STATUS_H

typedef enum {
	NM_PPP_STATUS_UNKNOWN,

	NM_PPP_STATUS_DEAD,
	NM_PPP_STATUS_INITIALIZE,
	NM_PPP_STATUS_SERIALCONN,
	NM_PPP_STATUS_DORMANT,
	NM_PPP_STATUS_ESTABLISH,
	NM_PPP_STATUS_AUTHENTICATE,
	NM_PPP_STATUS_CALLBACK,
	NM_PPP_STATUS_NETWORK,
	NM_PPP_STATUS_RUNNING,
	NM_PPP_STATUS_TERMINATE,
	NM_PPP_STATUS_DISCONNECT,
	NM_PPP_STATUS_HOLDOFF,
	NM_PPP_STATUS_MASTER
} NMPPPStatus;

#endif /* NM_PPP_STATUS_H */
