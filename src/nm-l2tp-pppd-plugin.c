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
 */

#include <config.h>
#define ___CONFIG_H__

/* pppd headers *sigh* */
#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>

#include "nm-default.h"

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include "nm-l2tp-service.h"
#include "nm-ppp-status.h"

#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

int plugin_init (void);

char pppd_version[] = VERSION;

/*****************************************************************************/

struct {
	int log_level;
	const char *log_prefix_token;
	GDBusProxy *proxy;
} gl/*lobal*/;

/*****************************************************************************/

#define _NMLOG(level, ...) \
    G_STMT_START { \
         if (gl.log_level >= (level)) { \
             syslog (nm_utils_syslog_coerce_from_nm (level), \
                     "nm-l2tp[%s] %-7s [helper-%ld] " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
                     gl.log_prefix_token, \
                     nm_utils_syslog_to_str (level), \
                     (long) getpid () \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
         } \
    } G_STMT_END

#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)
#define _LOGE(...) _NMLOG(LOG_ERR, __VA_ARGS__)

/*****************************************************************************/

static void
nm_phasechange (void *data, int arg)
{
	NMPPPStatus ppp_status = NM_PPP_STATUS_UNKNOWN;
	char *ppp_phase;

	g_return_if_fail (G_IS_DBUS_PROXY (gl.proxy));

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

	_LOGI ("phasechange: status %d / phase '%s'",
	       ppp_status, ppp_phase);

	if (ppp_status != NM_PPP_STATUS_UNKNOWN) {
		g_dbus_proxy_call (gl.proxy,
		                   "SetState",
		                   g_variant_new ("(u)", ppp_status),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   NULL,
		                   NULL, NULL);
	}
}

static void
nm_ip_up (void *data, int arg)
{
	guint32 pppd_made_up_address = htonl (0x0a404040 + ifunit);
	ipcp_options opts = ipcp_gotoptions[0];
	ipcp_options peer_opts = ipcp_hisoptions[0];
	GVariantBuilder builder;

	g_return_if_fail (G_IS_DBUS_PROXY (gl.proxy));

	_LOGI ("ip-up: event");

	if (!opts.ouraddr) {
		_LOGW ("ip-up: didn't receive an internal IP from pppd!");
		nm_phasechange (NULL, PHASE_DEAD);
		return;
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV,
	                       g_variant_new_string (ifname));

	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS,
	                       g_variant_new_uint32 (opts.ouraddr));

	/* Prefer the peer options remote address first, _unless_ pppd made the
	 * address up, at which point prefer the local options remote address,
	 * and if that's not right, use the made-up address as a last resort.
	 */
	if (peer_opts.hisaddr && (peer_opts.hisaddr != pppd_made_up_address)) {
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                       g_variant_new_uint32 (peer_opts.hisaddr));
	} else if (opts.hisaddr) {
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                       g_variant_new_uint32 (opts.hisaddr));
	} else if (peer_opts.hisaddr == pppd_made_up_address) {
		/* As a last resort, use the made-up address */
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                       g_variant_new_uint32 (peer_opts.ouraddr));
	}

	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,
	                       g_variant_new_uint32 (32));

	if (opts.dnsaddr[0] || opts.dnsaddr[1]) {
		guint32 dns[2];
		int len = 0;

		if (opts.dnsaddr[0])
			dns[len++] = opts.dnsaddr[0];
		if (opts.dnsaddr[1])
			dns[len++] = opts.dnsaddr[1];

		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_DNS,
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                  dns, len, sizeof (guint32)));
	}

	_LOGI ("ip-up: sending Ip4Config to NetworkManager-l2tp...");

	g_dbus_proxy_call (gl.proxy,
	                   "SetIp4Config",
	                   g_variant_new ("(a{sv})", &builder),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   NULL,
	                   NULL, NULL);
}

static int
get_chap_check (void)
{
	return 1;
}

static int
get_pap_check (void)
{
	return 1;
}

static int
get_credentials (char *username, char *password)
{
	const char *my_username = NULL;
	const char *my_password = NULL;
	size_t len;
	GVariant *ret;
	GError *error = NULL;

	if (!password) {
		/* pppd is checking pap support; return 1 for supported */
		g_return_val_if_fail (username, -1);
		return 1;
	}

	g_return_val_if_fail (username, -1);
	g_return_val_if_fail (G_IS_DBUS_PROXY (gl.proxy), -1);

	_LOGI ("passwd-hook: requesting credentials...");

	ret = g_dbus_proxy_call_sync (gl.proxy,
	                              "NeedSecrets",
	                              NULL,
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              NULL, &error);
	if (!ret) {
		_LOGW ("passwd-hook: could not get secrets: %s",
		       error->message);
		g_error_free (error);
		return -1;
	}

	_LOGI ("passwd-hook: got credentials from NetworkManager-l2tp");

	g_variant_get (ret, "(&s&s)", &my_username, &my_password);

	if (my_username) {
		len = strlen (my_username) + 1;
		len = len < MAXNAMELEN ? len : MAXNAMELEN;

		strncpy (username, my_username, len);
		username[len - 1] = '\0';
	}

	if (my_password) {
		len = strlen (my_password) + 1;
		len = len < MAXSECRETLEN ? len : MAXSECRETLEN;

		strncpy (password, my_password, len);
		password[len - 1] = '\0';
	}

	g_variant_unref (ret);

	return 1;
}

static void
nm_exit_notify (void *data, int arg)
{
	g_return_if_fail (G_IS_DBUS_PROXY (gl.proxy));

	_LOGI ("exit: cleaning up");
	g_clear_object (&gl.proxy);
}

int
plugin_init (void)
{
	GDBusConnection *bus;
	GError *error = NULL;
	const char *bus_name;

	nm_g_type_init ();

	g_return_val_if_fail (!gl.proxy, -1);

	bus_name = getenv ("NM_DBUS_SERVICE_L2TP");
	if (!bus_name)
		bus_name = NM_DBUS_SERVICE_L2TP;

	gl.log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
	                                             10, 0, LOG_DEBUG,
	                                             LOG_NOTICE);
	gl.log_prefix_token = getenv ("NM_VPN_LOG_PREFIX_TOKEN") ?: "???";

	_LOGI ("initializing");

	bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!bus) {
		_LOGE ("couldn't connect to system bus: %s",
		       error->message);
		g_error_free (error);
		return -1;
	}

	gl.proxy = g_dbus_proxy_new_sync (bus,
	                                  G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                  NULL,
	                                  bus_name,
	                                  NM_DBUS_PATH_L2TP_PPP,
	                                  NM_DBUS_INTERFACE_L2TP_PPP,
	                                  NULL, &error);
	g_object_unref (bus);

	if (!gl.proxy) {
		_LOGE ("couldn't create D-Bus proxy: %s",
		       error->message);
		g_error_free (error);
		return -1;
	}

	chap_passwd_hook = get_credentials;
	chap_check_hook = get_chap_check;
	pap_passwd_hook = get_credentials;
	pap_check_hook = get_pap_check;

	add_notifier (&phasechange, nm_phasechange, NULL);
	add_notifier (&ip_up_notifier, nm_ip_up, NULL);
	add_notifier (&exitnotify, nm_exit_notify, NULL);
	return 0;
}
