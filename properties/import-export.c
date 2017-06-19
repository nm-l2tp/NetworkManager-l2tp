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

#include "nm-default.h"

#include "import-export.h"

#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>

#include "nm-utils/nm-vpn-plugin-utils.h"

#define CONN_SECTION "connection"
#define VPN_SECTION "vpn"
#define IP4_SECTION "ip4"

/*
[connection]
name = my-l2tp-connection

[vpn]
gateway=my.gateway.org (str)
user=my_login (str)
refuse-eap=true (bool)
refuse-pap=true (bool)
refuse-chap=true (bool)
refuse-mschap=true (bool)
require-mppe=true (bool)
mru=1200 (int)
mtu=1200 (int)

ipsec-enabled=true (bool)
ipsec-gateway-id=192.168.0.1 (str)
ipsec-psk=my_psk (str)
ipsec-forceencaps=true (bool)

[ipv4]
method = auto (str)
dns = 192.168.0.1,8.8.8.8 (list)
dns-search = my_domain1,my_domain2 (list)
addresses = ???
routes = 192.168.0.0/24 via 192.168.0.1 metric 1,192.168.1.0/24 via 192.168.0.1 metric 2 (list with custom parser)
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
	{ NM_L2TP_KEY_MRU,               G_TYPE_UINT, FALSE },
	{ NM_L2TP_KEY_MTU,               G_TYPE_UINT, FALSE },
	/* { NM_L2TP_KEY_PASSWORD"-flags",  G_TYPE_UINT, FALSE }, */
	{ NM_L2TP_KEY_IPSEC_ENABLE,      G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_IPSEC_GATEWAY_ID,  G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_PSK,         G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_IKE,         G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_ESP,         G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_FORCEENCAPS, G_TYPE_BOOLEAN, FALSE },
	{ NULL,                          G_TYPE_NONE,   FALSE }
};

static VpnImportExportProperty ip4_properties[] = {
	{ NM_SETTING_IP_CONFIG_METHOD,             G_TYPE_STRING,  TRUE},
	{ NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, G_TYPE_BOOLEAN, FALSE},
	{ NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS,    G_TYPE_BOOLEAN, FALSE},
	{ NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, G_TYPE_BOOLEAN, FALSE},
	{ NM_SETTING_IP_CONFIG_NEVER_DEFAULT,      G_TYPE_BOOLEAN, FALSE},
	{ NULL,                                     G_TYPE_NONE,    FALSE }
 /* NM_SETTING_IP_CONFIG_DNS */
 /* NM_SETTING_IP_CONFIG_DNS_SEARCH */
 /* NM_SETTING_IP_CONFIG_ROUTES */
};

static void
ip4_import_error (GError **error, const char *message, const char *key, const char *val)
{
	g_set_error (error,
	             NMV_EDITOR_PLUGIN_ERROR,
	             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
	             message,
	             key,
	             val);
}

static void
ip4_route_import_error(GError **error, char *message, const char *val, char **routes)
{
	ip4_import_error (error, message, NM_SETTING_IP_CONFIG_ROUTES, val);
	g_strfreev (routes);
}

static gboolean
import_ip4 (GKeyFile *keyfile, NMSettingIPConfig *s_ip4, GError **error)
{
	char *str_val;
	int i;
#ifndef NM_VPN_OLD
	GError *local_error = NULL;
#endif

	for (i = 0; ip4_properties[i].name; i++){
		VpnImportExportProperty prop = ip4_properties[i];
		gboolean bool_val;

		if (!g_key_file_has_key (keyfile, IP4_SECTION, prop.name, error)){
			if (!prop.required)
				continue;

			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_MISSING_PROPERTY,
			             _("Required property %s missing"),
			             prop.name);
			return FALSE;
		}

		switch (prop.type) {
		case G_TYPE_STRING:
			str_val = g_key_file_get_string(keyfile, IP4_SECTION, prop.name, error);
			g_object_set (G_OBJECT (s_ip4),
			              prop.name, str_val,
			              NULL);
			g_free(str_val);
			break;
		case G_TYPE_BOOLEAN:
			bool_val = g_key_file_get_boolean(keyfile, IP4_SECTION, prop.name, error);
			if (!bool_val && !(*error)) /* If boolean value is FALSE */
				continue;
			if (!bool_val) {
				g_clear_error(error);
				str_val = g_key_file_get_string(keyfile, IP4_SECTION, prop.name, error);
				ip4_import_error (error,
				                  _("Property %s value '%s' can't be parsed as boolean."),
				                  prop.name,
				                  str_val);
				g_free(str_val);
				return FALSE;
			}
			g_object_set (G_OBJECT (s_ip4),
			              prop.name, bool_val,
			              NULL);
			break;
		}
	}

	if (g_key_file_has_key (keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_DNS, error)) {
		char **dnses;
		gsize length;

		dnses = g_key_file_get_string_list (keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_DNS,
		                                    &length, error);
		for (i=0; i<length; i++) {
#ifdef NM_VPN_OLD
			struct in_addr addr;
			if (!inet_aton (dnses[i], &addr)){
				ip4_import_error (error,
				                  _("Property '%s' value '%s' can't be parsed as IP address."),
				                  NM_SETTING_IP_CONFIG_DNS,
				                  dnses[i]);
				g_strfreev (dnses);
				return FALSE;
			}
			nm_setting_ip4_config_add_dns (s_ip4, addr.s_addr);
#else
			nm_setting_ip_config_add_dns (s_ip4, dnses[i]);
#endif
		}
		g_strfreev (dnses);
	}

	if (g_key_file_has_key (keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_DNS_SEARCH, error)) {
		char **dnses;
		gsize length;

		dnses = g_key_file_get_string_list (keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_DNS_SEARCH,
		                                    &length, error);
		for (i=0; i<length; i++)
#ifdef NM_VPN_OLD
			nm_setting_ip4_config_add_dns_search (s_ip4, (const char *)dnses[i]);
#else
			nm_setting_ip_config_add_dns_search (s_ip4, (const char *)dnses[i]);
#endif
		g_strfreev (dnses);
	}

	if (g_key_file_has_key (keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_ROUTES, error)) {
		char **routes;
		gsize length;
		struct in_addr dest, next_hop = { 0, };

		routes = g_key_file_get_string_list (keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_ROUTES,
		                                     &length, error);
		for (i=0; i<length; i++){
			NMIPRoute *route;
			guint32 prefix, metric = -1;
			char *ptr, *dest_s, *prefix_s, *next_hop_s = NULL, *metric_s;

			ptr = routes[i];
			/* 192.168.0.0/24 via 192.168.0.1 metric 1
			   ^          0^ 0    ^          0       ^
			   dest        prefix next_hop           metric*/

			/* Parse dest */
			dest_s = routes[i];
			ptr = index(ptr, '/');
			if (!ptr){
				ip4_route_import_error (error,
				                       _("Property '%s' value '%s' couldn't find netmask."),
				                       routes[i],
				                       routes);
				return FALSE;
			}
			*(ptr) = '\0'; 		/* terminate dest_s */
			ptr++;

			if (!inet_aton (dest_s, &dest)){
				ip4_route_import_error (error,
				                        _("Property '%s' value '%s' can't be parsed as IP address."),
				                        dest_s,
				                        routes);
				return FALSE;
			}

			/* Parse prefix */
			prefix_s = ptr;
			ptr = index(ptr, ' ');
			if (ptr){
				*(ptr) = '\0'; 		/* terminate prefix_s */
				ptr++;
			}
			errno = 0;
			prefix = strtol (prefix_s, NULL, 10);
			if (errno != 0 || prefix <=0 || prefix > 32){
				ip4_route_import_error (error,
				                        _("Property '%s' value '%s' can't be parsed as IP netmask."),
				                        prefix_s,
				                        routes);
				return FALSE;
			}
			while (ptr && *ptr == ' ')
				ptr++;

			/* Parse next_hop */
			if (ptr && !strncmp (ptr, "via ", 4)){	/* "via" */
				ptr += 4;
				while (ptr && *ptr == ' ')
					ptr++;
				next_hop_s = ptr;
				ptr = index(ptr, ' ');
				if (ptr){
					*ptr = '\0'; /* terminate next_hop */
					ptr++;
				}
				if (!inet_aton (next_hop_s, &next_hop)){
					ip4_route_import_error (error,
					                        _("Property '%s' value '%s' can't be parsed as IP address."),
					                        next_hop_s,
					                        routes);
					return FALSE;
				}
				while (ptr && *ptr == ' ')
					ptr++;
			}

			/* Parse metric */
			if (ptr && !strncmp(ptr, "metric ", 7)){ /* "metric" */
				ptr += 7;
				while (ptr && *ptr == ' ')
					ptr++;
				metric_s = ptr;
				ptr = index(ptr, ' ');
				if (ptr){
					*ptr = '\0'; /* terminate metric_s */
					ptr++;
				}
				errno = 0;
				metric = strtol (metric_s, NULL, 10);
				if (errno != 0){
					ip4_route_import_error (error,
					                        _("Property '%s' value '%s' can't be parsed as route metric."),
					                        metric_s,
					                        routes);
					return FALSE;
				}
				while (ptr && *ptr == ' ')
					ptr++;
			}
			if (ptr){
				ip4_route_import_error (error,
				                        _("Error parsing property '%s' value '%s'."),
				                        ptr,
				                        routes);
				return FALSE;
			}

#ifdef NM_VPN_OLD
			route = nm_ip4_route_new ();
			nm_ip4_route_set_dest(route, dest.s_addr);
			nm_ip4_route_set_prefix(route, prefix);
			if (next_hop.s_addr)
				nm_ip4_route_set_next_hop(route, next_hop.s_addr);
			if (metric != -1)
				nm_ip4_route_set_metric(route, metric);
			nm_setting_ip4_config_add_route (s_ip4, route);
#else
			route = nm_ip_route_new (AF_INET, dest_s, prefix, next_hop_s, metric, &local_error);
			if (route) {
				nm_setting_ip_config_add_route (s_ip4, route);
				nm_ip_route_unref (route);
			} else {
				ip4_route_import_error (error,
				                        _("Error parsing property '%s': %s."),
				                        local_error->message,
				                        routes);
				g_clear_error (&local_error);
				return FALSE;
			}
#endif
		}
		g_strfreev(routes);
	}
	return TRUE;
}

/**
 * Create new L2TP VPN connection using data from .ini - like file located at #path
 *
 * Returns: a newly allocated #NMConnection on success or %NULL on failure
 **/
NMConnection *
do_import (const char *path, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	NMSettingIPConfig *s_ip4;

	GKeyFile *keyfile;
	char *value;
	int i;

	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_file (keyfile, path, 0, error)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN,
		             _("does not look like a L2TP VPN connection (parse failed)"));
		return NULL;
	}

	connection = nm_simple_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_L2TP, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* g_message("Start importing L2TP."); */

	value = g_key_file_get_string(keyfile, CONN_SECTION, "id", error);
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_ID, value,
	              NULL);
	g_free (value);

	for (i = 0; vpn_properties[i].name; i++){
		VpnImportExportProperty prop = vpn_properties[i];
		int int_val;
		gboolean bool_val;

		if (!g_key_file_has_key (keyfile, VPN_SECTION, prop.name, error)){
			if (!prop.required)
				continue;

			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_MISSING_PROPERTY,
			             _("Required property %s missing"),
			             prop.name);
			g_key_file_free (keyfile);
			g_object_unref (connection);
			return NULL;
		}

		switch (prop.type) {
		case G_TYPE_STRING:
			value = g_key_file_get_string(keyfile, VPN_SECTION, prop.name, error);
			break;
		case G_TYPE_UINT:
			int_val = g_key_file_get_integer(keyfile, VPN_SECTION, prop.name, error);
			if (int_val == 0 && *error){
				g_clear_error(error);
				g_set_error (error,
				             NMV_EDITOR_PLUGIN_ERROR,
				             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
				             _("Property %s can't be parsed as integer."),
				             prop.name);
				g_key_file_free (keyfile);
				g_object_unref (connection);
				return NULL;
			}
			value = g_strdup_printf ("%d", int_val);
			break;
		case G_TYPE_BOOLEAN:
			bool_val = g_key_file_get_boolean(keyfile, VPN_SECTION, prop.name, error);
			if (!bool_val && !(*error)) /* If boolean value is FALSE */
				continue;
			if (!bool_val) {
				g_clear_error(error);
				g_set_error (error,
				             NMV_EDITOR_PLUGIN_ERROR,
				             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
				             _("Property %s can't be parsed as boolean. Only 'true' and 'false' allowed."),
				             prop.name);
				g_key_file_free (keyfile);
				g_object_unref (connection);
				return NULL;
			}
			value = g_strdup("yes");
			break;
		}

		/* TODO: add custom validators for int and string fields there, add special
		   "validator_flag" field to #vpn_properties and
		   then use switch "case validator_flag: validation_function() ..." */

		/* g_message("Import [%s]%s = %s", VPN_SECTION, prop.name, value); */
		nm_setting_vpn_add_data_item (s_vpn, prop.name, value);
		g_free (value);
	}

	if (!import_ip4(keyfile, s_ip4, error)){
		g_key_file_free (keyfile);
		g_object_unref (connection);
		return NULL;
	}

	/* g_message("Imported L2TP."); */

	return connection;
}

/**
 * Exports #NMSettingIPConfig s_ip4 to #GKeyFile keyfile (only VPN-related fields)
 *
 * Returns: %TRUE on success or %FALSE on failure
 **/
static gboolean
export_ip4(NMSettingIPConfig *s_ip4, GKeyFile *keyfile, GError **error)
{
	const char *str_val;
	gboolean bool_val;
	guint32 num_dns;
	guint32 num_dns_searches;
	guint32 num_routes;
	int i;

#ifdef NM_VPN_OLD
	str_val = nm_setting_ip4_config_get_method(s_ip4);

	g_key_file_set_string(keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_METHOD, str_val);

	num_dns = nm_setting_ip4_config_get_num_dns(s_ip4);
#else
	str_val = nm_setting_ip_config_get_method(s_ip4);

	g_key_file_set_string(keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_METHOD, str_val);

	num_dns = nm_setting_ip_config_get_num_dns(s_ip4);
#endif

	if (num_dns > 0){
		gchar *dnses[num_dns];

		for (i=0; i<num_dns; i++){
#ifdef NM_VPN_OLD
			struct in_addr addr;
			guint32 dns;

			dns = nm_setting_ip4_config_get_dns(s_ip4, i);
			addr.s_addr = dns;
			dnses[i] = g_strdup(inet_ntoa(addr));
#else
			dnses[i] = g_strdup(nm_setting_ip_config_get_dns(s_ip4, i));
#endif
		}
		g_key_file_set_string_list(keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_DNS,
		                           (const gchar * const*)dnses, num_dns);
		for (i=0; i<num_dns; i++)
			g_free(dnses[i]);
	}

#ifdef NM_VPN_OLD
	num_dns_searches = nm_setting_ip4_config_get_num_dns_searches(s_ip4);
#else
	num_dns_searches = nm_setting_ip_config_get_num_dns_searches(s_ip4);
#endif
	if (num_dns_searches > 0){
		const char *dnses[num_dns_searches];

		for (i=0; i<num_dns_searches; i++){
#ifdef NM_VPN_OLD
			dnses[i] = nm_setting_ip4_config_get_dns_search(s_ip4, i);
#else
			dnses[i] = nm_setting_ip_config_get_dns_search(s_ip4, i);
#endif
		}
		g_key_file_set_string_list(keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_DNS_SEARCH,
		                           dnses, num_dns_searches);
	}

#ifdef NM_VPN_OLD
	num_routes = nm_setting_ip4_config_get_num_routes(s_ip4);
#else
	num_routes = nm_setting_ip_config_get_num_routes(s_ip4);
#endif

	if (num_routes > 0){
		char *routes[num_routes];
		NMIPRoute *route;

		for (i=0; i<num_routes; i++){
			GString *route_s;
#ifdef NM_VPN_OLD
			guint32 dest, prefix, nhop, metric;
			struct in_addr addr;

			route = nm_setting_ip4_config_get_route(s_ip4, i);
			dest = nm_ip4_route_get_dest(route);
			prefix = nm_ip4_route_get_prefix(route);
			nhop = nm_ip4_route_get_next_hop(route);
			metric = nm_ip4_route_get_metric(route);

			/* dest and prefix are required */
			g_return_val_if_fail (dest, FALSE);
			g_return_val_if_fail (prefix, FALSE);

			route_s = g_string_new ("");

			addr.s_addr = dest;
			g_string_append_printf(route_s, "%s/%d", inet_ntoa(addr), prefix);

			if (nhop){
				addr.s_addr = nhop;
				g_string_append_printf(route_s, " via %s", inet_ntoa(addr));
			}
			if (metric)
				g_string_append_printf(route_s, " metric %d", metric);
#else
			route = nm_setting_ip_config_get_route(s_ip4, i);
			if (nm_ip_route_get_family (route) != AF_INET) {
				g_message("ignoring route #%d of %d: Not a IPv4 route", i, num_routes);
				continue;
			}
			route_s = g_string_new ("");
			g_string_append_printf(route_s, "%s/%d",
			                       nm_ip_route_get_dest (route),
			                       nm_ip_route_get_prefix (route));
			if (nm_ip_route_get_next_hop (route))
				g_string_append_printf(route_s, " via %s", nm_ip_route_get_next_hop (route));
			if (nm_ip_route_get_metric (route) != -1)
				g_string_append_printf(route_s, " metric %" PRId64, nm_ip_route_get_metric (route));
#endif
			routes[i] = g_string_free(route_s, FALSE);
			g_message("export route #%d of %d: %s", i, num_routes, routes[i]);
		}
		g_key_file_set_string_list(keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_ROUTES,
		                           (const gchar * const*)routes, num_routes);
		for (i=0; i<num_dns; i++)
			g_free(routes[i]);
	}

#ifdef NM_VPN_OLD
	bool_val = nm_setting_ip4_config_get_ignore_auto_routes(s_ip4);
#else
	bool_val = nm_setting_ip_config_get_ignore_auto_routes(s_ip4);
#endif
	g_key_file_set_boolean(keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, bool_val);

#ifdef NM_VPN_OLD
	bool_val = nm_setting_ip4_config_get_ignore_auto_dns(s_ip4);
#else
	bool_val = nm_setting_ip_config_get_ignore_auto_dns(s_ip4);
#endif
	g_key_file_set_boolean(keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, bool_val);

#ifdef NM_VPN_OLD
	bool_val = nm_setting_ip4_config_get_dhcp_send_hostname(s_ip4);
#else
	bool_val = nm_setting_ip_config_get_dhcp_send_hostname(s_ip4);
#endif
	g_key_file_set_boolean(keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, bool_val);

#ifdef NM_VPN_OLD
	bool_val = nm_setting_ip4_config_get_never_default(s_ip4);
#else
	bool_val = nm_setting_ip_config_get_never_default(s_ip4);
#endif
	g_key_file_set_boolean(keyfile, IP4_SECTION, NM_SETTING_IP_CONFIG_NEVER_DEFAULT, bool_val);


	return TRUE;
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
	NMSettingVpn *s_vpn;
	NMSettingIPConfig *s_ip4;

	GKeyFile *export_file;
	FILE *file;
	char *data;

	const char *value;
	int i;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	s_ip4 = (NMSettingIPConfig *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	s_vpn = (NMSettingVpn *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	export_file = g_key_file_new ();

	g_key_file_set_comment(export_file, NULL, NULL, NM_DBUS_SERVICE_L2TP, error);

	value = nm_setting_connection_get_id(s_con);
	g_key_file_set_string(export_file, CONN_SECTION, "id", value);

	for (i = 0; vpn_properties[i].name; i++){
		VpnImportExportProperty prop = vpn_properties[i];

		value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
		if (!value && prop.required){
			g_key_file_free(export_file);
			g_set_error(error,
			            NMV_EDITOR_PLUGIN_ERROR,
			            NMV_EDITOR_PLUGIN_ERROR_MISSING_PROPERTY,
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
			if (!strcmp(value, "yes"))
				g_key_file_set_boolean(export_file,
				                       VPN_SECTION,
				                       prop.name,
				                       TRUE);
			/* if key not set - assume as "no" */
			break;
		}
	}

	export_ip4(s_ip4, export_file, error);

	if (!(file = fopen (path, "w"))) {
		g_set_error(error,
		            NMV_EDITOR_PLUGIN_ERROR,
		            NMV_EDITOR_PLUGIN_ERROR_FAILED,
		            _("Couldn't open file for writing."));
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
