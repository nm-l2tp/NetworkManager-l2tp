/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <glib/gi18n-lib.h>

#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "import-export.h"
#include "nm-l2tp.h"
#include "../src/nm-l2tp-service.h"

#define CONN_SECTION "connection"
#define VPN_SECTION "vpn"
#define IP4_SECTION "ip4"

/*
[connection]
name = my-l2tp-connection

[vpn]
# password-flags = 1 (int)
noaccomp = true (bool)
nopcomp = true (bool)
no-vj-comp = true (bool)
refuse_eap = true (bool)
nobsdcomp = true (bool)
nodeflate = true (bool)
refuse-pap = true (bool)
user = my_login (str)
gateway = 192.168.0.1 (str)

ipsec-enabled = true (bool)
ipsec-group-name = GroupVPN (str)
ipsec-psk = my_psk (str) ????
ipsec-gateway-id = my_gateway (str)

[ipv4]
method = auto (str)
dns = 192.168.0.1,8.8.8.8 (list)
dns-search = my_domain1,my_domain2 (list)
addresses = ???
routes = 192.168.0.0/24 via 192.168.0.1,192.168.1.0/24 via 192.168.0.1 (list with custom parser)
ignore-auto-routes = true (list)
ignore-auto-dns = true (list)
???
 */
typedef struct {
	const char *name;
	GType type;
	gboolean required;
} VpnImportExportProperty;

static VpnImportExportProperty vpn_properties[] = {
	{ NM_L2TP_KEY_GATEWAY,           G_TYPE_STRING, TRUE },
	{ NM_L2TP_KEY_USER,              G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_DOMAIN,            G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_REFUSE_EAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_REFUSE_PAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_REFUSE_CHAP,       G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_REFUSE_MSCHAP,     G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_REFUSE_MSCHAPV2,   G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_REQUIRE_MPPE,      G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_REQUIRE_MPPE_40,   G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_REQUIRE_MPPE_128,  G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_MPPE_STATEFUL,     G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_NOBSDCOMP,         G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_NODEFLATE,         G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_NO_VJ_COMP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_NO_PCOMP,          G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_NO_ACCOMP,         G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_LCP_ECHO_FAILURE,  G_TYPE_UINT, FALSE },
	{ NM_L2TP_KEY_LCP_ECHO_INTERVAL, G_TYPE_UINT, FALSE },
	/* { NM_L2TP_KEY_PASSWORD"-flags",  G_TYPE_UINT, FALSE }, */
	{ NM_L2TP_KEY_IPSEC_ENABLE,      G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_IPSEC_GATEWAY_ID,  G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_GROUP_NAME,  G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_PSK,         G_TYPE_STRING, FALSE },
	{ NULL,                          G_TYPE_NONE,   FALSE }
};


NMConnection *
do_import (const char *path, char **lines, GError **error)
{
	return NULL;
}

/**
 * Exports L2TP connection #connection to .ini - like file named #path
 *
 * Returns: %TRUE on success or %FALSE on failure
 **/
gboolean
do_export (const char *path, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	NMSettingIP4Config *s_ip4;

	GKeyFile *export_file;
	FILE *file;
	char *data;

	const char *value;
	int i;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	/* s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG); */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	export_file = g_key_file_new ();

	value = nm_setting_connection_get_id(s_con);
	g_key_file_set_string(export_file, CONN_SECTION, "id", value);

	for (i = 0; vpn_properties[i].name; i++){
		VpnImportExportProperty prop = vpn_properties[i];

		value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
		if (!value && prop.required){
			g_key_file_free(export_file);
			g_set_error(error,
						0,
						0,
						_("Missing required property '%s'"),
						prop.name);
			return FALSE;
		}
		if (!value)
			continue;

		g_message("export %s = %s", prop.name, value);
		switch (prop.type) {
		case G_TYPE_STRING:
		case G_TYPE_UINT:
			g_key_file_set_string(export_file, VPN_SECTION, prop.name, value);
			break;
		case G_TYPE_BOOLEAN:
			g_key_file_set_boolean(export_file,
								   VPN_SECTION,
								   prop.name,
								   !strcmp(value, "yes") ? TRUE : FALSE);
			break;
		}
	}

	if (!(file = fopen (path, "w"))) {
		g_warning (_("Could not open file: %s"), path);
		g_key_file_free (export_file);
		return FALSE;
	}
	data = g_key_file_to_data (export_file, NULL, error);
	/* g_message("conf %s", data); */
	fputs (data, file);
	fclose (file);
	g_free (data);
	g_key_file_free (export_file);
	return TRUE;
}
