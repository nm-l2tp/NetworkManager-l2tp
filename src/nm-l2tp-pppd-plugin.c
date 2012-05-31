/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-l2tp-service - l2tp (and other pppd) integration with NetworkManager
 *
 * (C) 2007 - 2008 Novell, Inc.
 * (C) 2008 - 2009 Red Hat, Inc.
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
 * 
 */

#include <string.h>
#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>

#include "nm-l2tp-service.h"
#include "nm-ppp-status.h"

#include <nm-utils.h>

int plugin_init (void);

char pppd_version[] = VERSION;

static DBusGProxy *proxy = NULL;

static void
nm_phasechange (void *data, int arg)
{
	NMPPPStatus ppp_status = NM_PPP_STATUS_UNKNOWN;
	char *ppp_phase;

	g_return_if_fail (DBUS_IS_G_PROXY (proxy));

	switch (arg) {
	case PHASE_DEAD:
		ppp_status = NM_PPP_STATUS_DEAD;
		ppp_phase = "dead";
		break;
	case PHASE_INITIALIZE:
		ppp_status = NM_PPP_STATUS_INITIALIZE;
		ppp_phase = "initialize";
		break;
	case PHASE_SERIALCONN:
		ppp_status = NM_PPP_STATUS_SERIALCONN;
		ppp_phase = "serial connection";
		break;
	case PHASE_DORMANT:
		ppp_status = NM_PPP_STATUS_DORMANT;
		ppp_phase = "dormant";
		break;
	case PHASE_ESTABLISH:
		ppp_status = NM_PPP_STATUS_ESTABLISH;
		ppp_phase = "establish";
		break;
	case PHASE_AUTHENTICATE:
		ppp_status = NM_PPP_STATUS_AUTHENTICATE;
		ppp_phase = "authenticate";
		break;
	case PHASE_CALLBACK:
		ppp_status = NM_PPP_STATUS_CALLBACK;
		ppp_phase = "callback";
		break;
	case PHASE_NETWORK:
		ppp_status = NM_PPP_STATUS_NETWORK;
		ppp_phase = "network";
		break;
	case PHASE_RUNNING:
		ppp_status = NM_PPP_STATUS_RUNNING;
		ppp_phase = "running";
		break;
	case PHASE_TERMINATE:
		ppp_status = NM_PPP_STATUS_TERMINATE;
		ppp_phase = "terminate";
		break;
	case PHASE_DISCONNECT:
		ppp_status = NM_PPP_STATUS_DISCONNECT;
		ppp_phase = "disconnect";
		break;
	case PHASE_HOLDOFF:
		ppp_status = NM_PPP_STATUS_HOLDOFF;
		ppp_phase = "holdoff";
		break;
	case PHASE_MASTER:
		ppp_status = NM_PPP_STATUS_MASTER;
		ppp_phase = "master";
		break;

	default:
		ppp_phase = "unknown";
		break;
	}

	g_message ("nm-l2tp-ppp-plugin: (%s): status %d / phase '%s'",
	           __func__,
	           ppp_status,
	           ppp_phase);

	if (ppp_status != NM_PPP_STATUS_UNKNOWN) {
		dbus_g_proxy_call_no_reply (proxy, "SetState",
		                            G_TYPE_UINT, ppp_status,
		                            G_TYPE_INVALID,
		                            G_TYPE_INVALID);
	}
}

static GValue *
str_to_gvalue (const char *str)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static GValue *
uint_to_gvalue (guint32 i)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, i);

	return val;
}

static void
value_destroy (gpointer data)
{
	GValue *val = (GValue *) data;

	g_value_unset (val);
	g_slice_free (GValue, val);
}

static void
nm_ip_up (void *data, int arg)
{
	guint32 pppd_made_up_address = htonl (0x0a404040 + ifunit);
	ipcp_options opts = ipcp_gotoptions[0];
	ipcp_options peer_opts = ipcp_hisoptions[0];
	GHashTable *hash;
	GArray *array;
	GValue *val;

	g_return_if_fail (DBUS_IS_G_PROXY (proxy));

	g_message ("nm-l2tp-ppp-plugin: (%s): ip-up event", __func__);

	if (!opts.ouraddr) {
		g_warning ("nm-l2tp-ppp-plugin: (%s): didn't receive an internal IP from pppd!", __func__);
		return;
	}

	hash = g_hash_table_new_full (g_str_hash, g_str_equal,
							NULL, value_destroy);

	g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, 
					 str_to_gvalue (ifname));

	/* Prefer the peer options remote address first, _unless_ pppd made the
	 * address up, at which point prefer the local options remote address,
	 * and if that's not right, use the made-up address as a last resort.
	 */
	if (peer_opts.hisaddr && (peer_opts.hisaddr != pppd_made_up_address)) {
		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                     uint_to_gvalue (peer_opts.hisaddr));
	} else if (opts.hisaddr) {
		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                     uint_to_gvalue (opts.hisaddr));
	} else if (peer_opts.hisaddr == pppd_made_up_address) {
		/* As a last resort, use the made-up address */
		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                     uint_to_gvalue (peer_opts.hisaddr));
	}

	g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, 
					 uint_to_gvalue (opts.ouraddr));

	g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, uint_to_gvalue (32));

	if (opts.dnsaddr[0] || opts.dnsaddr[1]) {
		array = g_array_new (FALSE, FALSE, sizeof (guint32));

		if (opts.dnsaddr[0])
			g_array_append_val (array, opts.dnsaddr[0]);
		if (opts.dnsaddr[1])
			g_array_append_val (array, opts.dnsaddr[1]);

		val = g_slice_new0 (GValue);
		g_value_init (val, DBUS_TYPE_G_UINT_ARRAY);
		g_value_set_boxed (val, array);

		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_DNS, val);
	}

	/* Default MTU to 1400, which is also what Windows XP/Vista use */
	g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_MTU, uint_to_gvalue (1400));

	g_message ("nm-l2tp-ppp-plugin: (%s): sending Ip4Config to NetworkManager-l2tp...", __func__);

	dbus_g_proxy_call_no_reply (proxy, "SetIp4Config",
	                            DBUS_TYPE_G_MAP_OF_VARIANT, hash, G_TYPE_INVALID,
	                            G_TYPE_INVALID);

	g_hash_table_destroy (hash);
}

static int
get_chap_check(void)
{
	return 1;
}

static int
get_pap_check(void)
{
	return 1;
}

static int
get_credentials (char *username, char *password)
{
	char *my_username = NULL;
	char *my_password = NULL;
	size_t len;
	GError *err = NULL;

	if (username && !password) {
		/* pppd is checking pap support; return 1 for supported */
		return 1;
	}

	g_return_val_if_fail (DBUS_IS_G_PROXY (proxy), -1);

	g_message ("nm-l2tp-ppp-plugin: (%s): passwd-hook, requesting credentials...", __func__);

	dbus_g_proxy_call (proxy, "NeedSecrets", &err,
	                   G_TYPE_INVALID,
	                   G_TYPE_STRING, &my_username,
	                   G_TYPE_STRING, &my_password,
	                   G_TYPE_INVALID);

	if (err) {
		g_warning ("nm-l2tp-ppp-plugin: (%s): could not get secrets: (%d) %s",
		           __func__,
		           err ? err->code : -1,
		           err->message ? err->message : "(unknown)");
		g_error_free (err);
		return -1;
	}

	g_message ("nm-l2tp-ppp-plugin: (%s): got credentials from NetworkManager-l2tp", __func__);

	if (my_username) {
		len = strlen (my_username) + 1;
		len = len < MAXNAMELEN ? len : MAXNAMELEN;

		strncpy (username, my_username, len);
		username[len - 1] = '\0';

		g_free (my_username);
	}

	if (my_password) {
		len = strlen (my_password) + 1;
		len = len < MAXSECRETLEN ? len : MAXSECRETLEN;

		strncpy (password, my_password, len);
		password[len - 1] = '\0';

		g_free (my_password);
	}

	return 1;
}

static void
nm_exit_notify (void *data, int arg)
{
	g_return_if_fail (DBUS_IS_G_PROXY (proxy));

	g_message ("nm-l2tp-ppp-plugin: (%s): cleaning up", __func__);

	g_object_unref (proxy);
	proxy = NULL;
}

int
plugin_init (void)
{
	DBusGConnection *bus;
	GError *err = NULL;

	g_type_init ();

	g_message ("nm-l2tp-ppp-plugin: (%s): initializing", __func__);

	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!bus) {
		g_warning ("nm-l2tp-pppd-plugin: (%s): couldn't connect to system bus: (%d) %s",
		           __func__,
		           err ? err->code : -1,
		           err && err->message ? err->message : "(unknown)");
		g_error_free (err);
		return -1;
	}

	proxy = dbus_g_proxy_new_for_name (bus,
								NM_DBUS_SERVICE_L2TP_PPP,
								NM_DBUS_PATH_L2TP_PPP,
								NM_DBUS_INTERFACE_L2TP_PPP);

	dbus_g_connection_unref (bus);

	chap_passwd_hook = get_credentials;
	chap_check_hook = get_chap_check;
	pap_passwd_hook = get_credentials;
	pap_check_hook = get_pap_check;

	add_notifier (&phasechange, nm_phasechange, NULL);
	add_notifier (&ip_up_notifier, nm_ip_up, NULL);
	add_notifier (&exitnotify, nm_exit_notify, proxy);

	return 0;
}
