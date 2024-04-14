/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Dan Williams <dcbw@redhat.com>
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

typedef enum {
    NM_L2TP_L2TP_DAEMON_UNKNOWN = 0,
    NM_L2TP_L2TP_DAEMON_XL2TPD,
    NM_L2TP_L2TP_DAEMON_KL2TPD,
} NML2tpL2tpDaemon;

NML2tpIpsecDaemon check_ipsec_daemon(const char *path);

gboolean require_libreswan_ipsec_auto(const char *path);

const char *nm_find_ipsec(void);

const char *nm_find_l2tpd(NML2tpL2tpDaemon *l2tp_daemon);

#endif /* __UTILS_H__ */
