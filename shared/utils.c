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

#include "nm-default.h"

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"

NML2tpIpsecDaemon
check_ipsec_daemon (const char *path)
{
	const char *argv[] = { path, "--version", NULL };
	g_autofree char *output = NULL;

	if (g_spawn_sync (NULL, (char **) argv, NULL, 0, NULL, NULL, &output, NULL, NULL, NULL)) {
		if (!output)
			return NM_L2TP_IPSEC_DAEMON_UNKNOWN;

		if (strstr (output, " strongSwan "))
			return NM_L2TP_IPSEC_DAEMON_STRONGSWAN;

		if (strstr (output, " Libreswan "))
			return NM_L2TP_IPSEC_DAEMON_LIBRESWAN;

		if (strstr (output, " Openswan "))
			return NM_L2TP_IPSEC_DAEMON_OPENSWAN;
	}
	return NM_L2TP_IPSEC_DAEMON_UNKNOWN;
}

const char *
nm_find_ipsec (void)
{
	static const char *ipsec_binary_paths[] =
		{
			"/sbin/ipsec",
			"/usr/sbin/ipsec",
			"/usr/local/sbin/ipsec",
			"/sbin/strongswan",
			"/usr/sbin/strongswan",
			"/usr/local/sbin/strongswan",
			NULL
		};

	const char  **ipsec_binary = ipsec_binary_paths;

	while (*ipsec_binary != NULL) {
		if (g_file_test (*ipsec_binary, G_FILE_TEST_EXISTS))
			break;
		ipsec_binary++;
	}

	return *ipsec_binary;
}

const char *
nm_find_l2tpd (void)
{
	static const char *l2tp_binary_paths[] =
		{
			"/sbin/xl2tpd",
			"/usr/sbin/xl2tpd",
			"/usr/local/sbin/xl2tpd",
			NULL
		};

	const char  **l2tp_binary = l2tp_binary_paths;

	while (*l2tp_binary != NULL) {
		if (g_file_test (*l2tp_binary, G_FILE_TEST_EXISTS))
			break;
		l2tp_binary++;
	}

	return *l2tp_binary;
}

