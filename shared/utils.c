// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
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

	if (path == NULL)
		return NM_L2TP_IPSEC_DAEMON_UNKNOWN;

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
			"/bin/ipsec",
			"/usr/bin/ipsec",
			"/usr/local/bin/ipsec",
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
			"/bin/xl2tpd",
			"/usr/bin/xl2tpd",
			"/usr/local/bin/xl2tpd",
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

