/* SPDX-License-Identifier: GPL-2.0-or-later */
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
check_ipsec_daemon(const char *path)
{
    const char *     argv[] = {path, "--version", NULL};
    g_autofree char *output = NULL;

    if (path == NULL)
        return NM_L2TP_IPSEC_DAEMON_UNKNOWN;

    if (g_spawn_sync(NULL, (char **) argv, NULL, 0, NULL, NULL, &output, NULL, NULL, NULL)) {
        if (!output)
            return NM_L2TP_IPSEC_DAEMON_UNKNOWN;

        if (strstr(output, "strongSwan") != NULL)
            return NM_L2TP_IPSEC_DAEMON_STRONGSWAN;

        if (strstr(output, "Libreswan") != NULL)
            return NM_L2TP_IPSEC_DAEMON_LIBRESWAN;

        if (strstr(output, "Openswan") != NULL)
            return NM_L2TP_IPSEC_DAEMON_OPENSWAN;
    }
    return NM_L2TP_IPSEC_DAEMON_UNKNOWN;
}

const char *
nm_find_ipsec(void)
{
    static const char *ipsec_binary_paths[] = {"/usr/bin/ipsec",
                                               "/sbin/ipsec",
                                               "/usr/sbin/ipsec",
                                               "/usr/local/sbin/ipsec",
                                               "/sbin/strongswan",
                                               "/usr/sbin/strongswan",
                                               "/usr/local/sbin/strongswan",
                                               NULL};

    const char **ipsec_binary = ipsec_binary_paths;

    while (*ipsec_binary != NULL) {
        if (g_file_test(*ipsec_binary, G_FILE_TEST_EXISTS))
            break;
        ipsec_binary++;
    }

    return *ipsec_binary;
}

const char *
nm_find_l2tpd(NML2tpL2tpDaemon *l2tp_daemon)
{
    char **l2tp_binary;

    static const char *kl2tp_binary_paths[] = {"/usr/bin/kl2tpd",
                                               "/sbin/kl2tpd",
                                               "/usr/sbin/kl2tpd",
                                               "/usr/local/sbin/kl2tpd",
                                               NULL};

    static const char *xl2tp_binary_paths[] = {"/usr/bin/xl2tpd",
                                               "/sbin/xl2tpd",
                                               "/usr/sbin/xl2tpd",
                                               "/usr/local/sbin/xl2tpd",
                                               NULL};

    l2tp_binary = (char **) kl2tp_binary_paths;
    while (*l2tp_binary != NULL) {
        if (g_file_test(*l2tp_binary, G_FILE_TEST_EXISTS)) {
            if (l2tp_daemon != NULL)
                *l2tp_daemon = NM_L2TP_L2TP_DAEMON_KL2TPD;
            return *l2tp_binary;
        }
        l2tp_binary++;
    }

    l2tp_binary = (char **) xl2tp_binary_paths;
    while (*l2tp_binary != NULL) {
        if (g_file_test(*l2tp_binary, G_FILE_TEST_EXISTS)) {
            if (l2tp_daemon != NULL)
                *l2tp_daemon = NM_L2TP_L2TP_DAEMON_XL2TPD;
            return *l2tp_binary;
        }
        l2tp_binary++;
    }

    return NULL;
}
