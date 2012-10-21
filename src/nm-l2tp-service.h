/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-l2tp-service - L2TP VPN integration with NetworkManager
 *
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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifndef NM_L2TP_PLUGIN_H
#define NM_L2TP_PLUGIN_H

#include <glib.h>
#include <glib-object.h>
#include <nm-vpn-plugin.h>

#define NM_TYPE_L2TP_PLUGIN            (nm_l2tp_plugin_get_type ())
#define NM_L2TP_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_L2TP_PLUGIN, NML2tpPlugin))
#define NM_L2TP_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_L2TP_PLUGIN, NML2tpPluginClass))
#define NM_IS_L2TP_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_L2TP_PLUGIN))
#define NM_IS_L2TP_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_L2TP_PLUGIN))
#define NM_L2TP_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_L2TP_PLUGIN, NML2tpPluginClass))

/* For the pppd plugin <-> VPN plugin service */
#define DBUS_TYPE_G_MAP_OF_VARIANT (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))

#define NM_DBUS_SERVICE_L2TP_PPP    "org.freedesktop.NetworkManager.l2tp-ppp"
#define NM_DBUS_PATH_L2TP_PPP       "/org/freedesktop/NetworkManager/l2tp/ppp"
#define NM_DBUS_INTERFACE_L2TP_PPP  "org.freedesktop.NetworkManager.l2tp.ppp"


/* For the NM <-> VPN plugin service */
#define NM_DBUS_SERVICE_L2TP    "org.freedesktop.NetworkManager.l2tp"
#define NM_DBUS_INTERFACE_L2TP  "org.freedesktop.NetworkManager.l2tp"
#define NM_DBUS_PATH_L2TP       "/org/freedesktop/NetworkManager/l2tp"

#define NM_L2TP_KEY_GATEWAY           "gateway"
#define NM_L2TP_KEY_USER              "user"
#define NM_L2TP_KEY_PASSWORD          "password"
#define NM_L2TP_KEY_DOMAIN            "domain"
#define NM_L2TP_KEY_REFUSE_EAP        "refuse-eap"
#define NM_L2TP_KEY_REFUSE_PAP        "refuse-pap"
#define NM_L2TP_KEY_REFUSE_CHAP       "refuse-chap"
#define NM_L2TP_KEY_REFUSE_MSCHAP     "refuse-mschap"
#define NM_L2TP_KEY_REFUSE_MSCHAPV2   "refuse-mschapv2"
#define NM_L2TP_KEY_REQUIRE_MPPE      "require-mppe"
#define NM_L2TP_KEY_REQUIRE_MPPE_40   "require-mppe-40"
#define NM_L2TP_KEY_REQUIRE_MPPE_128  "require-mppe-128"
#define NM_L2TP_KEY_MPPE_STATEFUL     "mppe-stateful"
#define NM_L2TP_KEY_NOBSDCOMP         "nobsdcomp"
#define NM_L2TP_KEY_NODEFLATE         "nodeflate"
#define NM_L2TP_KEY_NO_VJ_COMP        "no-vj-comp"
#define NM_L2TP_KEY_NO_PCOMP          "nopcomp"
#define NM_L2TP_KEY_NO_ACCOMP         "noaccomp"
#define NM_L2TP_KEY_LCP_ECHO_FAILURE  "lcp-echo-failure"
#define NM_L2TP_KEY_LCP_ECHO_INTERVAL "lcp-echo-interval"

#define NM_L2TP_KEY_IPSEC_ENABLE      "ipsec-enabled"
#define NM_L2TP_KEY_IPSEC_GATEWAY_ID  "ipsec-gateway-id"
#define NM_L2TP_KEY_IPSEC_GROUP_NAME  "ipsec-group-name"
#define NM_L2TP_KEY_IPSEC_PSK         "ipsec-psk"


typedef struct {
	NMVPNPlugin parent;
} NML2tpPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NML2tpPluginClass;

GType nm_l2tp_plugin_get_type (void);

NML2tpPlugin *nm_l2tp_plugin_new (void);

#endif /* NM_L2TP_PLUGIN_H */
