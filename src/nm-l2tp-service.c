/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-l2tp-service - L2TP VPN integration with NetworkManager
 *
 * Geo Carncross <geocar@gmail.com>
 * Alexey Torkhov <atorkhov@gmail.com>
 * Based on work by Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2008 - 2009 Red Hat, Inc.
 * (C) Copyright 2011 Alexey Torkhov <atorkhov@gmail.com>
 * (C) Copyright 2011 Geo Carncross <geocar@gmail.com>
 * (C) Copyright 2012 Sergey Prokhorov <me@seriyps.ru>
 * (C) Copyright 2014 Nathan Dorfman <ndorf@rtfm.net>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <locale.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <glib/gi18n.h>

#include <NetworkManager.h>
#include <nm-vpn-service-plugin.h>

#include "nm-l2tp-service.h"
#include "nm-ppp-status.h"
#include "nm-l2tp-pppd-service-dbus.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

#define PATH_PREFIX "PATH=/usr/local/sbin:/usr/sbin:/sbin"

static gboolean debug = FALSE;

/********************************************************/
/* ppp plugin <-> l2tp-service object                   */
/********************************************************/

/* We have a separate object to handle ppp plugin requests from
 * historical reason, because dbus-glib didn't allow multiple
 * interfaces registed on one GObject.
 */

#define NM_TYPE_L2TP_PPP_SERVICE            (nm_l2tp_ppp_service_get_type ())
#define NM_L2TP_PPP_SERVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_L2TP_PPP_SERVICE, NML2tpPppService))
#define NM_L2TP_PPP_SERVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_L2TP_PPP_SERVICE, NML2tpPppServiceClass))
#define NM_IS_L2TP_PPP_SERVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_L2TP_PPP_SERVICE))
#define NM_IS_L2TP_PPP_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_L2TP_PPP_SERVICE))
#define NM_L2TP_PPP_SERVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_L2TP_PPP_SERVICE, NML2tpPppServiceClass))

typedef struct {
	GObject parent;
} NML2tpPppService;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*plugin_alive) (NML2tpPppService *self);
	void (*ppp_state) (NML2tpPppService *self, guint32 state);
	void (*ip4_config) (NML2tpPppService *self, GVariant *config_hash);
} NML2tpPppServiceClass;

GType nm_l2tp_ppp_service_get_type (void);

G_DEFINE_TYPE (NML2tpPppService, nm_l2tp_ppp_service, G_TYPE_OBJECT)

static gboolean handle_need_secrets (NMDBusNetworkManagerL2tpPpp *object,
                                     GDBusMethodInvocation *invocation,
                                     gpointer user_data);

static gboolean handle_set_state (NMDBusNetworkManagerL2tpPpp *object,
                                  GDBusMethodInvocation *invocation,
                                  guint32 arg_state,
                                  gpointer user_data);

static gboolean handle_set_ip4_config (NMDBusNetworkManagerL2tpPpp *object,
                                       GDBusMethodInvocation *invocation,
                                       GVariant *arg_config,
                                       gpointer user_data);

#include "nm-l2tp-pppd-service-dbus.h"

#define NM_L2TP_PPP_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_L2TP_PPP_SERVICE, NML2tpPppServicePrivate))

typedef struct {
	char *username;
	char *domain;
	char *password;
	/* D-Bus stuff */
	NMDBusNetworkManagerL2tpPpp *dbus_skeleton;
} NML2tpPppServicePrivate;

enum {
	PLUGIN_ALIVE,
	PPP_STATE,
	IP4_CONFIG,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

static gboolean
nm_l2tp_ipsec_error(GError **error, const char *msg) {
	g_set_error_literal (error,
			NM_VPN_PLUGIN_ERROR,
			NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
			_(msg));
	return FALSE;
}

static gboolean
_service_cache_credentials (NML2tpPppService *self,
							NMConnection *connection,
							GError **error)
{
	NML2tpPppServicePrivate *priv = NM_L2TP_PPP_SERVICE_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	const char *username, *password, *domain;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);

	s_vpn = (NMSettingVpn *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (!s_vpn) {
		return nm_l2tp_ipsec_error(error, "Could not load NetworkManager connection settings.");
	}

	/* Username; try L2TP specific username first, then generic username */
	username = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER);
	if (!username || !*username) {
		username = nm_setting_vpn_get_user_name (s_vpn);
		if (!username || !*username) {
			return nm_l2tp_ipsec_error(error, "Missing VPN username.");
		}
	}

	password = nm_setting_vpn_get_secret (s_vpn, NM_L2TP_KEY_PASSWORD);
	if (!password || !*password) {
		return nm_l2tp_ipsec_error(error, "Missing or invalid VPN password.");
	}

	domain = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_DOMAIN);
	if (domain && *domain) priv->domain = g_strdup(domain);

	priv->username = g_strdup(username);
	priv->password = g_strdup(password);
	return TRUE;
}

static NML2tpPppService *
nm_l2tp_ppp_service_new (NMConnection *connection,
                         GError **error)
{
	NML2tpPppService *self = NULL;
	NML2tpPppServicePrivate *priv;
	GDBusConnection *bus;
	GDBusProxy *proxy;
	GVariant *ret;

	bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, error);
	if (!bus)
		return NULL;

	proxy = g_dbus_proxy_new_sync (bus,
	                               G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                               G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                               NULL,
	                               "org.freedesktop.DBus",
	                               "/org/freedesktop/DBus",
	                               "org.freedesktop.DBus",
	                               NULL, error);
	if (!proxy)
		goto out;

	ret = g_dbus_proxy_call_sync (proxy,
				      "RequestName",
				      g_variant_new ("(su)", NM_DBUS_SERVICE_L2TP_PPP, 0),
				      G_DBUS_CALL_FLAGS_NONE, -1,
				      NULL, error);
	if (!ret) {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		g_warning (_("Could not register D-Bus service name.  Message: %s"), (*error)->message);
		goto out;
	}

	g_variant_unref (ret);

	self = (NML2tpPppService *) g_object_new (NM_TYPE_L2TP_PPP_SERVICE, NULL);
	g_assert(self);
	priv = NM_L2TP_PPP_SERVICE_GET_PRIVATE (self);

	priv->dbus_skeleton = nmdbus_network_manager_l2tp_ppp_skeleton_new ();
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton),
	                                       bus,
	                                       NM_DBUS_PATH_L2TP_PPP,
	                                       error))
		goto out;

	g_dbus_connection_register_object (bus, NM_DBUS_PATH_L2TP_PPP,
					   nmdbus_network_manager_l2tp_ppp_interface_info (),
					   NULL, NULL, NULL, NULL);

	g_signal_connect (priv->dbus_skeleton, "handle-need-secrets", G_CALLBACK (handle_need_secrets), self);
	g_signal_connect (priv->dbus_skeleton, "handle-set-state", G_CALLBACK (handle_set_state), self);
	g_signal_connect (priv->dbus_skeleton, "handle-set-ip4-config", G_CALLBACK (handle_set_ip4_config), self);

out:
	g_clear_object (&bus);
	return self;
}

static void
nm_l2tp_ppp_service_init (NML2tpPppService *self)
{
}

static void
nm_l2tp_ppp_service_dispose (GObject *object)
{
	NML2tpPppServicePrivate *priv = NM_L2TP_PPP_SERVICE_GET_PRIVATE (object);

	g_signal_handlers_disconnect_by_func (priv->dbus_skeleton, handle_need_secrets, object);
	g_signal_handlers_disconnect_by_func (priv->dbus_skeleton, handle_set_state, object);
	g_signal_handlers_disconnect_by_func (priv->dbus_skeleton, handle_set_ip4_config, object);

	G_OBJECT_CLASS (nm_l2tp_ppp_service_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NML2tpPppServicePrivate *priv = NM_L2TP_PPP_SERVICE_GET_PRIVATE (object);

	/* Get rid of the cached username and password */
	g_free (priv->username);
	if (priv->password) {
		memset (priv->password, 0, strlen (priv->password));
		g_free (priv->password);
	}
	g_free (priv->domain);

	G_OBJECT_CLASS (nm_l2tp_ppp_service_parent_class)->finalize (object);
}

static void
nm_l2tp_ppp_service_class_init (NML2tpPppServiceClass *service_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (service_class);

	g_type_class_add_private (service_class, sizeof (NML2tpPppServicePrivate));

	/* virtual methods */
	object_class->dispose = nm_l2tp_ppp_service_dispose;
	object_class->finalize = finalize;

	/* Signals */
	signals[PLUGIN_ALIVE] = 
		g_signal_new ("plugin-alive", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NML2tpPppServiceClass, plugin_alive),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[PPP_STATE] = 
		g_signal_new ("ppp-state", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NML2tpPppServiceClass, ppp_state),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[IP4_CONFIG] = 
		g_signal_new ("ip4-config", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NML2tpPppServiceClass, ip4_config),
		              NULL, NULL,
		              NULL,
		              G_TYPE_NONE, 1, G_TYPE_VARIANT);
}

static gboolean
handle_need_secrets (NMDBusNetworkManagerL2tpPpp *object,
                     GDBusMethodInvocation *invocation,
                     gpointer user_data)

{
	NML2tpPppService *self = NM_L2TP_PPP_SERVICE (user_data);
	NML2tpPppServicePrivate *priv = NM_L2TP_PPP_SERVICE_GET_PRIVATE (self);
	char *username = NULL, *password = NULL;
	GError *error = NULL;

	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	if (!*priv->username || !*priv->password) {
		g_set_error (&error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             "%s",
		             _("No cached credentials."));
		g_dbus_method_invocation_take_error (invocation, error);
		return FALSE;
	}

	/* Success */
	if (priv->domain && *priv->domain) {
		username = g_strdup_printf ("%s\\%s", priv->domain, priv->username);
	} else {
		username = g_strdup (priv->username);
	}
	password = g_strdup (priv->password);

	g_dbus_method_invocation_return_value (invocation,
	                                       g_variant_new ("(ss)", username, password));
	g_free (username);
	g_free (password);
	return TRUE;
}

static gboolean
handle_set_state (NMDBusNetworkManagerL2tpPpp *object,
                  GDBusMethodInvocation *invocation,
                  guint32 arg_state,
                  gpointer user_data)
{
	NML2tpPppService *self = NM_L2TP_PPP_SERVICE (user_data);

	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);
	g_signal_emit (G_OBJECT (self), signals[PPP_STATE], 0, arg_state);
	g_dbus_method_invocation_return_value (invocation, NULL);

	return TRUE;
}

static gboolean
handle_set_ip4_config (NMDBusNetworkManagerL2tpPpp *object,
                       GDBusMethodInvocation *invocation,
                       GVariant *arg_config,
                       gpointer user_data)
{
	NML2tpPppService *self = NM_L2TP_PPP_SERVICE (user_data);

	g_message (_("L2TP service (IP Config Get) reply received."));
	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	/* Just forward the pppd plugin config up to our superclass; no need to modify it */
	g_signal_emit (G_OBJECT (self), signals[IP4_CONFIG], 0, arg_config);

	return TRUE;
}


/********************************************************/
/* The VPN plugin service                               */
/********************************************************/

G_DEFINE_TYPE (NML2tpPlugin, nm_l2tp_plugin, NM_TYPE_VPN_SERVICE_PLUGIN);

typedef struct {
	GPid pid_l2tpd;
	gboolean ipsec_up;
	guint32 ppp_timeout_handler;
	guint32 naddr;		/* We resolve GW addr before pass it to xl2tpd. network byte-order */
	char *saddr;
	NML2tpPppService *service;
	NMConnection *connection;
} NML2tpPluginPrivate;

#define NM_L2TP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_L2TP_PLUGIN, NML2tpPluginPrivate))

#define NM_L2TP_PPPD_PLUGIN PLUGINDIR "/nm-l2tp-pppd-plugin.so"
#define NM_L2TP_WAIT_PPPD 10000 /* 10 seconds */
#define L2TP_SERVICE_SECRET_TRIES "l2tp-service-secret-tries"

typedef struct {
	const char *name;
	GType type;
	gboolean required;
} ValidProperty;

static ValidProperty valid_properties[] = {
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
	{ NM_L2TP_KEY_PASSWORD"-flags",  G_TYPE_UINT, FALSE },
	{ NM_L2TP_KEY_IPSEC_ENABLE,      G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_IPSEC_GATEWAY_ID,  G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_GROUP_NAME,  G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_PSK,         G_TYPE_STRING, FALSE },
	{ NULL,                          G_TYPE_NONE,   FALSE }
};

static ValidProperty valid_secrets[] = {
	{ NM_L2TP_KEY_PASSWORD,          G_TYPE_STRING, FALSE },
	{ NULL,                          G_TYPE_NONE,   FALSE }
};

static gboolean
validate_gateway (const char *gateway)
{
	const char *p = gateway;

	if (!gateway || !*gateway) return FALSE;

	/* Ensure it's a valid DNS name or IP address */
	p = gateway;
	while (*p) {
		if (!isalnum (*p) && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

static gboolean
validate_ipsec_id (const char *id)
{
	const char *p = id;

	if (!id || !*id) return TRUE;

	/* Ensure it's a valid id-name */
	p = id;
	while (*p) {
		if (!isalnum (*p) && (*p != '_') && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	/* Search property named 'key' in 'valid_properties'/'valid_secrets' array
	   XXX: use hash? */
	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			if (!strcmp (prop.name, NM_L2TP_KEY_IPSEC_PSK))
				return; /* valid */

			if (   !strcmp (prop.name, NM_L2TP_KEY_GATEWAY)
			    && !validate_gateway (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid gateway '%s'"),
				             key);
				return;
			}
			if (   !strcmp (prop.name, NM_L2TP_KEY_IPSEC_GROUP_NAME)
			    && !validate_ipsec_id (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid ipsec-group-name '%s'"),
				             key);
				return;
			}
			if (   !strcmp (prop.name, NM_L2TP_KEY_IPSEC_GATEWAY_ID)
			    && !validate_ipsec_id (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid ipsec-gateway-id '%s'"),
				             key);
				return;
			}
		case G_TYPE_UINT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid integer property '%s'"),
			             key);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid boolean property '%s' (not yes or no)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property '%s' type %s"),
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property '%s' invalid or not supported"),
		             key);
	}
}

static gboolean
nm_l2tp_properties_validate (NMSettingVpn *s_vpn,
                             GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };
	int i;

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		return nm_l2tp_ipsec_error(error, "No VPN configuration options.");
	}

	if (*error) return FALSE;

	/* Ensure required properties exist */
	for (i = 0; valid_properties[i].name; i++) {
		ValidProperty prop = valid_properties[i];
		const char *value;

		if (!prop.required) continue;

		value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
		if (!value || !*value) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Missing required option '%s'."),
			             prop.name);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
nm_l2tp_secrets_validate (NMSettingVpn *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		return nm_l2tp_ipsec_error(error, "No VPN secrets!");
	}

	return *error ? FALSE : TRUE;
}

static void
nm_l2tp_stop_ipsec(void);

static void
l2tpd_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NML2tpPlugin *plugin = NM_L2TP_PLUGIN (user_data);
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;
	pid_t my_pid = getpid ();
	char *filename;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			g_warning (_("xl2tpd exited with error code %d"), error);
	}
	else if (WIFSTOPPED (status))
		g_warning (_("xl2tpd stopped unexpectedly with signal %d"), WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		g_warning (_("xl2tpd died with signal %d"), WTERMSIG (status));
	else
		g_warning (_("xl2tpd died from an unknown cause"));

	/* Reap child if needed. */
	waitpid (priv->pid_l2tpd, NULL, WNOHANG);
	priv->pid_l2tpd = 0;

	if(priv->ipsec_up) {
		nm_l2tp_stop_ipsec();
	}

	/* Cleaning up config files */
	filename = g_strdup_printf ("/var/run/nm-xl2tpd.conf.%d", my_pid);
	unlink(filename);
	g_free(filename);

	filename = g_strdup_printf ("/var/run/nm-ppp-options.xl2tpd.%d", my_pid);
	unlink(filename);
	g_free(filename);

	filename = g_strdup_printf ("/var/run/nm-ipsec-l2tp.%d/ipsec.conf", my_pid);
	unlink(filename);
	g_free(filename);

	filename = g_strdup_printf ("/var/run/nm-ipsec-l2tp.%d/ipsec.secrets", my_pid);
	unlink(filename);
	g_free(filename);

	filename = g_strdup_printf ("/var/run/nm-ipsec-l2tp.%d", my_pid);
	rmdir(filename);
	g_free(filename);

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 16:
		/* hangup */
		// FIXME: better failure reason
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
		break;
	}
}

static inline const char *
nm_find_ipsec (void)
{
	static const char *ipsec_binary_paths[] =
		{
			"/sbin/ipsec",
			"/usr/sbin/ipsec",
			"/usr/local/sbin/ipsec",
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

static inline const char *
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

static gboolean
pppd_timed_out (gpointer user_data)
{
	NML2tpPlugin *plugin = NM_L2TP_PLUGIN (user_data);

	g_warning (_("pppd timeout. Looks like pppd didn't initialize our dbus module"));
	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT);

	return FALSE;
}

static gboolean
nm_l2tp_resolve_gateway (NML2tpPlugin *plugin,
						 NMSettingVpn *s_vpn,
						 GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	const char *p, *src;
	gboolean is_name = FALSE;
	struct in_addr naddr;
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int err;
	char buf[INET_ADDRSTRLEN + 1];

	p = src = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_GATEWAY);
	g_return_val_if_fail (src != NULL, FALSE);

	while (*p) {
		if (*p != '.' && !isdigit (*p)) {
			is_name = TRUE;
			break;
		}
		p++;
	}

	if (is_name == FALSE) {
		errno = 0;
		if (inet_pton (AF_INET, src, &naddr) <= 0) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
			             _("couldn't convert L2TP VPN gateway IP address '%s' (%d)"),
			             src, errno);
			return FALSE;
		}
		priv->naddr = naddr.s_addr;
		priv->saddr = g_strdup (src);
		return TRUE;
	}

	/* It's a hostname, resolve it */
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_ADDRCONFIG;
	err = getaddrinfo (src, NULL, &hints, &result);
	if (err != 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("couldn't look up L2TP VPN gateway IP address '%s' (%d)"),
		             src, err);
		return FALSE;
	}

	/* If the hostname resolves to multiple IP addresses, use the first one.
	 * FIXME: maybe we just want to use a random one instead?
	 */
	memset (&naddr, 0, sizeof (naddr));
	for (rp = result; rp; rp = rp->ai_next) {
		if (   (rp->ai_family == AF_INET)
		    && (rp->ai_addrlen == sizeof (struct sockaddr_in))) {
			struct sockaddr_in *inptr = (struct sockaddr_in *) rp->ai_addr;

			memcpy (&naddr, &(inptr->sin_addr), sizeof (struct in_addr));
			break;
		}
	}
	freeaddrinfo (result);

	if (naddr.s_addr == 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("no usable addresses returned for L2TP VPN gateway '%s'"),
		             src);
		return FALSE;
	}

	memset (buf, 0, sizeof (buf));
	errno = 0;
	if (inet_ntop (AF_INET, &naddr, buf, sizeof (buf) - 1) == NULL) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("no usable addresses returned for L2TP VPN gateway '%s' (%d)"),
		             src, errno);
		return FALSE;
	}

	g_message(_("Use '%s' as a gateway"), buf);

	priv->naddr = naddr.s_addr;
	priv->saddr = g_strdup (buf);
	return TRUE;
}

static void
free_args (GPtrArray *args)
{
	int i;

	if (!args)
		return;

	for (i = 0; i < args->len; i++)
		g_free (g_ptr_array_index (args, i));
	g_ptr_array_free (args, TRUE);
}


static void
nm_l2tp_stop_ipsec(void)
{
	const char *ipsec_binary;
	char session_name[128];
	GPtrArray *whack_argv;

	g_message("ipsec prepare for shut down");
	if (!(ipsec_binary=nm_find_ipsec())) return;

	sprintf(session_name, "nm-ipsec-l2tp-%d", getpid());
	whack_argv = g_ptr_array_new ();
	g_ptr_array_add (whack_argv, (gpointer) g_strdup (ipsec_binary));
	g_ptr_array_add (whack_argv, (gpointer) g_strdup ("whack"));
	g_ptr_array_add (whack_argv, (gpointer) g_strdup ("--delete"));
	g_ptr_array_add (whack_argv, (gpointer) g_strdup ("--name"));
	g_ptr_array_add (whack_argv, (gpointer) g_strdup (session_name));
	g_ptr_array_add (whack_argv, NULL);

	if (!g_spawn_sync (NULL, (char **) whack_argv->pdata, NULL,
	                    0, NULL, NULL,
			    NULL,NULL,
			    NULL, NULL)) {
		free_args (whack_argv);
		return;
	}

	g_message("ipsec shut down");
}

static gboolean
nm_l2tp_start_ipsec(NML2tpPlugin *plugin,
                            NMSettingVpn *s_vpn,
                            GError **error)
{
	// NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	const char *ipsec_binary;
	const char *value;
	char tmp_secrets[128];
	char session_name[128];
	char cmdbuf[256];
	int sys = 0;
	int fd;
	FILE *fp;
	gboolean rc = FALSE;

	if (!(ipsec_binary=nm_find_ipsec())) {
		return nm_l2tp_ipsec_error(error, "Could not find the ipsec binary. Is Openswan installed?");
	}

	sprintf(session_name, "nm-ipsec-l2tp-%d", getpid());

	sys = system("test -e /var/run/pluto/ipsec.info && . /var/run/pluto/ipsec.info;"
			PATH_PREFIX "; export PATH;"
			"if [ \"x$defaultrouteaddr\" = \"x\" ]; then ipsec setup restart; fi");
	if (sys) {
		return nm_l2tp_ipsec_error(error, "Could not restart the ipsec service.");
	}

	sys = system(PATH_PREFIX " ipsec whack --listen");
	if (sys) {
		return nm_l2tp_ipsec_error(error, "Could not talk to IPsec key exchange service.");
	}

	/* the way this works is sadly very messy
	   we replace the user's /etc/ipsec.secrets file
	   we ask openswan to reload the secrets,
	   we whack in our connection,
	   we then replace the secrets and ask openswan to reload them
	*/
	sprintf(tmp_secrets, "/etc/ipsec.secrets.%d",getpid());
	if(-1==rename("/etc/ipsec.secrets", tmp_secrets) && errno != EEXIST) {
		return nm_l2tp_ipsec_error(error, "Could not save existing /etc/ipsec.secrets file.");
	}

	fp = NULL;
	if ((fd = open("/etc/ipsec.secrets", O_CREAT | O_EXCL | O_WRONLY, 0600)) >= 0) {
		if (NULL == (fp = fdopen(fd, "w"))) close(fd);
	}
	if (NULL == fp) {
		rename(tmp_secrets, "/etc/ipsec.secrets");
		return nm_l2tp_ipsec_error(error, "Could not write /etc/ipsec.secrets file.");
	}
	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_GROUP_NAME);
	fprintf(fp, "%s%s ",value?"@":"", value?value:"%any");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_GATEWAY_ID);
	fprintf(fp, "%s%s ",value?"@":"", value?value:"%any");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_PSK);
	if(!value)value="";
	fprintf(fp, ": PSK \"%s\"\n",value);
	fclose(fp);
	close(fd);

	sys = system(PATH_PREFIX " ipsec secrets");
	if (!sys) {
		sprintf(cmdbuf, PATH_PREFIX " ipsec auto "
				" --config /var/run/nm-ipsec-l2tp.%d/ipsec.conf --verbose"
				" --add '%s'", getpid(),session_name);
		sys = system(cmdbuf);
		if (!sys) {
			sprintf(cmdbuf, PATH_PREFIX " ipsec auto "
					" --config /var/run/nm-ipsec-l2tp.%d/ipsec.conf --verbose"
					" --up '%s'",getpid(),session_name);
			sys = system(cmdbuf);
			if (!sys) {
				rc = TRUE;
				g_message(_("ipsec ready for action"));
			} else {
				nm_l2tp_ipsec_error(error, "Could not establish IPsec tunnel.");
			}
		} else {
			nm_l2tp_ipsec_error(error, "Could not configure IPsec tunnel.");
		}
	} else {
		nm_l2tp_ipsec_error(error, "Could not load new IPsec secret.");
	}

	if (rename(tmp_secrets, "/etc/ipsec.secrets") ||
			system(PATH_PREFIX " ipsec secrets")) {
		g_warning(_("Could not restore saved /etc/ipsec.secrets from %s."), _(tmp_secrets));
	}

	return rc;
}

static gboolean
nm_l2tp_start_l2tpd_binary (NML2tpPlugin *plugin,
                            NMSettingVpn *s_vpn,
                            GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	GPid pid;
	const char *l2tpd_binary;
	GPtrArray *l2tpd_argv;
	pid_t my_pid = getpid ();

	l2tpd_binary = nm_find_l2tpd ();
	if (!l2tpd_binary) {
		return nm_l2tp_ipsec_error(error, "Could not find the xl2tpd binary.");
	}

	l2tpd_argv = g_ptr_array_new ();
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup (l2tpd_binary));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup ("-D"));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup ("-c"));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup_printf ("/var/run/nm-xl2tpd.conf.%d", my_pid));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup ("-C"));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup_printf ("/var/run/nm-xl2tpd_l2tp-control.%d", my_pid));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup ("-p")); /* pid file named using pid? */
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup_printf ("/var/run/nm-xl2tpd_pid.%d", my_pid));
	g_ptr_array_add (l2tpd_argv, NULL);

	if (!g_spawn_async (NULL, (char **) l2tpd_argv->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error)) {
		free_args (l2tpd_argv);
		return FALSE;
	}
	free_args (l2tpd_argv);

	g_message(_("xl2tpd started with pid %d"), pid);

	NM_L2TP_PLUGIN_GET_PRIVATE (plugin)->pid_l2tpd = pid;
	g_child_watch_add (pid, l2tpd_watch_cb, plugin);

	priv->ppp_timeout_handler = g_timeout_add (NM_L2TP_WAIT_PPPD, pppd_timed_out, plugin);

	return TRUE;
}


static inline void
write_config_option (int fd, const char *format, ...)
{
	char * 	string;
	va_list	args;
	int		x;

	va_start (args, format);
	string = g_strdup_vprintf (format, args);
	x = write (fd, string, strlen (string));
	g_free (string);
	va_end (args);
}

typedef struct {
	const char *name;
	GType type;
	const char *write_to_config;
} PPPOpt;

static PPPOpt ppp_options[] = {
	{NM_L2TP_KEY_REFUSE_EAP, G_TYPE_BOOLEAN, "refuse-eap\n"},
	{NM_L2TP_KEY_REFUSE_PAP, G_TYPE_BOOLEAN, "refuse-pap\n"},
	{NM_L2TP_KEY_REFUSE_CHAP, G_TYPE_BOOLEAN, "refuse-chap\n"},
	{NM_L2TP_KEY_REFUSE_MSCHAP, G_TYPE_BOOLEAN, "refuse-mschap\n"},
	{NM_L2TP_KEY_REFUSE_MSCHAPV2, G_TYPE_BOOLEAN, "refuse-mschap-v2\n"},
	{NM_L2TP_KEY_REQUIRE_MPPE, G_TYPE_BOOLEAN, "require-mppe\n"},
	{NM_L2TP_KEY_REQUIRE_MPPE_40, G_TYPE_BOOLEAN, "require-mppe-40\n"},
	{NM_L2TP_KEY_REQUIRE_MPPE_128, G_TYPE_BOOLEAN, "require-mppe-128\n"},
	{NM_L2TP_KEY_MPPE_STATEFUL, G_TYPE_BOOLEAN, "mppe-stateful\n"},
	{NM_L2TP_KEY_NOBSDCOMP, G_TYPE_BOOLEAN, "nobsdcomp\n"},
	{NM_L2TP_KEY_NODEFLATE, G_TYPE_BOOLEAN, "nodeflate\n"},
	{NM_L2TP_KEY_NO_VJ_COMP, G_TYPE_BOOLEAN, "novj\n"},
	{NM_L2TP_KEY_NO_PCOMP, G_TYPE_BOOLEAN, "nopcomp\n"},
	{NM_L2TP_KEY_NO_ACCOMP, G_TYPE_BOOLEAN, "noaccomp\n"},
	{NULL, G_TYPE_NONE, NULL}
};

/**
 * Check that specified UDP socket in 0.0.0.0 is not used and we can bind to it.
 **/
static gboolean
is_port_free(int port)
{
	struct sockaddr_in addr;
	int sock;
	g_message ("Check port %d", port);
	sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (!sock){
		g_warning (_("Can-not create new test socket"));
		return FALSE;
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind (sock, (struct sockaddr *) &addr, sizeof (addr)) == -1){
		g_message ("Can't bind to port %d", port);
		return FALSE;
	}
	close(sock);				/* unbind */

	return TRUE;
}

/* XXX: currently unused! May be useful if l2tp client doesn't accept 0 as port number
static int
get_free_l2tp_port(void)
{
	int port = 1701;

	while (!is_port_free (port) && port < 65535)
		port++;

	if (port == 65535) // oh no..
		return -1;
	g_message("found free port %d", port);
	return port;
}
*/

static gboolean
nm_l2tp_config_write (NML2tpPlugin *plugin,
					  NMSettingVpn *s_vpn,
                      GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	NML2tpPppServicePrivate *service_priv = NULL;
	char *filename;
	pid_t pid = getpid ();
	const char *value;
	// const char *username;
	gint conf_fd = -1;
	gint ipsec_fd = -1;
	gint pppopt_fd = -1;
	int port;
	int i;

	filename = g_strdup_printf ("/var/run/nm-ipsec-l2tp.%d", pid);
	mkdir(filename,0700);
	g_free (filename);

	filename = g_strdup_printf ("/var/run/nm-ipsec-l2tp.%d/ipsec.conf", pid);
	ipsec_fd = open (filename, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	g_free (filename);
	if (ipsec_fd == -1) {
		return nm_l2tp_ipsec_error(error, "Could not write ipsec config.");
	}
	write_config_option (ipsec_fd, "version 2.0\n"
"config setup\n"
"  nat_traversal=yes\n"
"  force_keepalive=yes\n"
"  protostack=netkey\n"
"  keep_alive=60\n"
"\n");
	write_config_option (ipsec_fd, "conn nm-ipsec-l2tp-%d\n", pid);
	write_config_option (ipsec_fd,
"  auto=add\n"
"  type=transport\n"
"  auth=esp\n"
"  pfs=no\n"
"  authby=secret\n"
"  keyingtries=0\n"
"  left=%%defaultroute\n"
"  leftprotoport=udp/l2tp\n"
"  rightprotoport=udp/l2tp\n");
	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_GROUP_NAME);
	if(value)write_config_option (ipsec_fd, "  leftid=@%s\n", value);
	/* value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_GATEWAY); */
	write_config_option (ipsec_fd, "  right=%s\n", priv->saddr);
	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_GATEWAY_ID);
	if(value)write_config_option (ipsec_fd, "  rightid=@%s\n", value);
	write_config_option (ipsec_fd,
"  esp=3des-sha1\n"
"  keyexchange=ike\n"
"  ike=3des-sha1-modp1024\n"
"  aggrmode=no\n"
"  forceencaps=yes\n");



	filename = g_strdup_printf ("/var/run/nm-xl2tpd.conf.%d", pid);
	conf_fd = open (filename, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	g_free (filename);

	if (conf_fd == -1) {
		close(ipsec_fd);
		return nm_l2tp_ipsec_error(error, "Could not write xl2tpd config.");
	}

	filename = g_strdup_printf ("/var/run/nm-ppp-options.xl2tpd.%d", pid);
	pppopt_fd = open (filename, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	g_free (filename);

	if (pppopt_fd == -1) {
		close(ipsec_fd);
		close(conf_fd);
		return nm_l2tp_ipsec_error(error, "Could not write ppp options.");
	}

	/* L2TP options */
	write_config_option (conf_fd, "[global]\n");
	write_config_option (conf_fd, "access control = yes\n");

	/* Check that xl2tpd's default port 1701 is free, if not - use 0 (ephemeral random port) */
	/* port = get_free_l2tp_port(); */
	port = 1701;
	if (!is_port_free (port)){
		port = 0;
		g_warning("Port 1701 is busy, use ephemeral.");
	}
	write_config_option (conf_fd, "port = %d\n", port);
	if (debug){
		/* write_config_option (conf_fd, "debug network = yes\n"); */
		write_config_option (conf_fd, "debug state = yes\n");
		write_config_option (conf_fd, "debug tunnel = yes\n");
		write_config_option (conf_fd, "debug avp = yes\n");
	}

	write_config_option (conf_fd, "[lac l2tp]\n");

    /* value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_GATEWAY); */
	write_config_option (conf_fd, "lns = %s\n", priv->saddr);

	if (priv->service)
		service_priv = NM_L2TP_PPP_SERVICE_GET_PRIVATE (priv->service);
	if (service_priv && *service_priv->username) {
		write_config_option (conf_fd, "name = %s\n", service_priv->username);
	}
	if (debug)
		write_config_option (conf_fd, "ppp debug = yes\n");
	write_config_option (conf_fd, "pppoptfile = /var/run/nm-ppp-options.xl2tpd.%d\n", pid);
	write_config_option (conf_fd, "autodial = yes\n");
	write_config_option (conf_fd, "tunnel rws = 8\n");
	write_config_option (conf_fd, "tx bps = 100000000\n");
	write_config_option (conf_fd, "rx bps = 100000000\n");

	/* PPP options */
	if (debug)
		write_config_option (pppopt_fd, "debug\n");

	write_config_option (pppopt_fd, "ipparam nm-l2tp-service-%d\n", pid);

	write_config_option (pppopt_fd, "nodetach\n");
	write_config_option (pppopt_fd, "lock\n");
	write_config_option (pppopt_fd, "usepeerdns\n");
	write_config_option (pppopt_fd, "noipdefault\n");
	write_config_option (pppopt_fd, "nodefaultroute\n");

	/* Don't need to auth the L2TP server */
	write_config_option (pppopt_fd, "noauth\n");

	/* pppd and xl2tpd on Linux require this option to support Android and iOS clients,
	   and pppd on Linux clients won't work without the same option */
	write_config_option (pppopt_fd, "noccp\n");

	if (service_priv && *service_priv->username) {
		write_config_option (pppopt_fd, "name %s\n", service_priv->username);
	}

	for(i=0; ppp_options[i].name; i++){
		value = nm_setting_vpn_get_data_item (s_vpn, ppp_options[i].name);
		if (value && !strcmp (value, "yes"))
			write_config_option (pppopt_fd, ppp_options[i].write_to_config);
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_LCP_ECHO_FAILURE);
	if (value && *value) {
		long int tmp_int;

		/* Convert to integer and then back to string for security's sake
		 * because strtol ignores some leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			write_config_option (pppopt_fd, "lcp-echo-failure %ld\n", tmp_int);
		} else {
			g_warning (_("failed to convert lcp-echo-failure value '%s'"), value);
		}
	} else {
		write_config_option (pppopt_fd, "lcp-echo-failure 0\n");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_LCP_ECHO_INTERVAL);
	if (value && *value) {
		long int tmp_int;

		/* Convert to integer and then back to string for security's sake
		 * because strtol ignores some leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			write_config_option (pppopt_fd, "lcp-echo-interval %ld\n", tmp_int);
		} else {
			g_warning (_("failed to convert lcp-echo-interval value '%s'"), value);
		}
	} else {
		write_config_option (pppopt_fd, "lcp-echo-interval 0\n");
	}

	write_config_option (pppopt_fd, "plugin %s\n", NM_L2TP_PPPD_PLUGIN);

	close(ipsec_fd);
	close(conf_fd);
	close(pppopt_fd);

	return TRUE;
}

static void
remove_timeout_handler (NML2tpPlugin *plugin)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	
	if (priv->ppp_timeout_handler) {
		g_source_remove (priv->ppp_timeout_handler);
		priv->ppp_timeout_handler = 0;
	}
}

static void
service_plugin_alive_cb (NML2tpPppService *service,
                         NML2tpPlugin *plugin)
{
	remove_timeout_handler (plugin);
}

static void
service_ppp_state_cb (NML2tpPppService *service,
                      guint32 ppp_state,
                      NML2tpPlugin *plugin)
{
	if (ppp_state == NM_PPP_STATUS_DEAD || ppp_state == NM_PPP_STATUS_DISCONNECT)
		nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
}

static void
service_ip4_config_cb (NML2tpPppService *service,
                       GVariant *config,
                       NMVpnServicePlugin *plugin)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	GVariantIter iter;
	const char *key;
	GVariant *value;
	GVariantBuilder builder;
	GVariant *new_config;

	if (!config)
		return;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_iter_init (&iter, config);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &value)) {
		g_variant_builder_add (&builder, "{sv}", key, value);
		g_variant_unref (value);
	}

	/* Insert the external VPN gateway into the table, which the pppd plugin
	 * simply doesn't know about.
	 */
	g_variant_builder_add (&builder, "{sv}", NM_L2TP_KEY_GATEWAY, g_variant_new_uint32 (priv->naddr));
	new_config = g_variant_builder_end (&builder);
	g_variant_ref_sink (new_config);

	nm_vpn_service_plugin_set_ip4_config (plugin, new_config);
	g_variant_unref (new_config);
}

static gboolean
real_connect (NMVpnServicePlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	const char *value;

	if (getenv ("NM_PPP_DUMP_CONNECTION") || debug)
		nm_connection_dump (connection);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);

	if (!nm_l2tp_properties_validate (s_vpn, error))
		return FALSE;

	if (!nm_l2tp_secrets_validate (s_vpn, error))
		return FALSE;

	/* Start our pppd plugin helper service */
	if (priv->service)
		g_object_unref (priv->service);
	if (priv->connection) {
		g_object_unref (priv->connection);
		priv->connection = NULL;
	}

	priv->service = nm_l2tp_ppp_service_new (connection, error);
	if (!priv->service) {
		return nm_l2tp_ipsec_error(error, "Could not start pppd plugin helper service.");
	}

	priv->connection = g_object_ref (connection);

	g_signal_connect (G_OBJECT (priv->service), "plugin-alive", G_CALLBACK (service_plugin_alive_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ppp-state", G_CALLBACK (service_ppp_state_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ip4-config", G_CALLBACK (service_ip4_config_cb), plugin);

	/* Cache the username and password so we can relay the secrets to the pppd
	 * plugin when it asks for them.
	 */
	if (!_service_cache_credentials (priv->service, connection, error))
		return FALSE;

	if (!nm_l2tp_resolve_gateway (NM_L2TP_PLUGIN (plugin), s_vpn, error))
		return FALSE;

	if (!nm_l2tp_config_write (NM_L2TP_PLUGIN (plugin), s_vpn, error))
		return FALSE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_ENABLE);
	g_message(_("ipsec enable flag: %s"), value?value:"(null)");
	if(value && !strcmp(value,"yes")) {
		g_message(_("starting ipsec"));
		if (!nm_l2tp_start_ipsec(NM_L2TP_PLUGIN (plugin), s_vpn, error))
			return FALSE;
		priv->ipsec_up = TRUE;
	}

	if (!nm_l2tp_start_l2tpd_binary (NM_L2TP_PLUGIN (plugin), s_vpn, error))
		return FALSE;

	return TRUE;
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSetting *s_vpn;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_L2TP_KEY_PASSWORD, &flags, NULL);

	/* Don't need the password if it's not required */
	if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		return FALSE;

	/* Don't need the password if we already have one */
	if (nm_setting_vpn_get_secret (NM_SETTING_VPN (s_vpn), NM_L2TP_KEY_PASSWORD))
		return FALSE;

	/* Otherwise we need a password */
	*setting_name = NM_SETTING_VPN_SETTING_NAME;
	return TRUE;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0){
		g_warning("Kill process %d by SIGKILL", pid);
		kill (pid, SIGKILL);
	}

	return FALSE;
}

static gboolean
real_disconnect (NMVpnServicePlugin   *plugin,
			  GError       **err)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid_l2tpd) {
		if (kill (priv->pid_l2tpd, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid_l2tpd));
		else
			kill (priv->pid_l2tpd, SIGKILL);

		g_message(_("Terminated l2tp daemon with PID %d."), priv->pid_l2tpd);
		priv->pid_l2tpd = 0;
	}

	if(priv->ipsec_up) {
		nm_l2tp_stop_ipsec();
	}

	if (priv->connection) {
		g_object_unref (priv->connection);
		priv->connection = NULL;
	}

	if (priv->service) {
		g_object_unref (priv->service);
		priv->service = NULL;
	}

	return TRUE;
}

static void
state_changed_cb (GObject *object, NMVpnServiceState state, gpointer user_data)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (object);

	switch (state) {
	case NM_VPN_SERVICE_STATE_STARTED:
		remove_timeout_handler (NM_L2TP_PLUGIN (object));
		break;
	case NM_VPN_SERVICE_STATE_UNKNOWN:
	case NM_VPN_SERVICE_STATE_INIT:
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
	case NM_VPN_SERVICE_STATE_STOPPING:
	case NM_VPN_SERVICE_STATE_STOPPED:
		remove_timeout_handler (NM_L2TP_PLUGIN (object));
		if (priv->connection) {
			g_object_unref (priv->connection);
			priv->connection = NULL;
		}
		if (priv->service) {
			g_object_unref (priv->service);
			priv->service = NULL;
		}
		break;
	default:
		break;
	}
}

static void
dispose (GObject *object)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (object);

	if (priv->connection)
		g_object_unref (priv->connection);

	if (priv->service)
		g_object_unref (priv->service);

	if (priv->saddr)
		g_free (priv->saddr);

	G_OBJECT_CLASS (nm_l2tp_plugin_parent_class)->dispose (object);
}

static void
nm_l2tp_plugin_init (NML2tpPlugin *plugin)
{
}

static void
nm_l2tp_plugin_class_init (NML2tpPluginClass *l2tp_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (l2tp_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (l2tp_class);

	g_type_class_add_private (object_class, sizeof (NML2tpPluginPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	parent_class->connect    = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
}

NML2tpPlugin *
nm_l2tp_plugin_new (void)
{
	NML2tpPlugin *plugin;

	plugin = g_object_new (NM_TYPE_L2TP_PLUGIN,
	                       NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME,
	                       NM_DBUS_SERVICE_L2TP,
	                       NULL);
	if (plugin)
		g_signal_connect (G_OBJECT (plugin), "state-changed", G_CALLBACK (state_changed_cb), NULL);
	return plugin;
}

static void
quit_mainloop (NML2tpPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NML2tpPlugin *plugin;
	GMainLoop *main_loop;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_L2TP_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	    _("nm-l2tp-service provides L2TP VPN capability with optional IPSec support to NetworkManager."));

	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (getenv ("NM_PPP_DEBUG"))
		debug = TRUE;

	if (debug)
		g_message ("nm-l2tp-service (version " DIST_VERSION ") starting...");

	plugin = nm_l2tp_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	main_loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), main_loop);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}
