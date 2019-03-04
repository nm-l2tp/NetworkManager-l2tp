/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2010 Red Hat, Inc.
 * (C) Copyright 2019 Douglas Kosovic <doug@uq.edu.au>
 */

#ifndef __UTILS_H__
#define __UTILS_H__

typedef enum {
        NM_L2TP_IPSEC_DAEMON_UNKNOWN = 0,
        NM_L2TP_IPSEC_DAEMON_STRONGSWAN,
        NM_L2TP_IPSEC_DAEMON_LIBRESWAN,
        NM_L2TP_IPSEC_DAEMON_OPENSWAN,
} NML2tpIpsecDaemon;

NML2tpIpsecDaemon
check_ipsec_daemon (const char *path);

const char *
nm_find_ipsec (void);

const char *
nm_find_l2tpd (void);

#endif /* __UTILS_H__ */

