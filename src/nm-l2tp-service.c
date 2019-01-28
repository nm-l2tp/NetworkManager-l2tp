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
 * (C) Copyright 2016 - 2019 Douglas Kosovic <doug@uq.edu.au>
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
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include <nm-setting-vpn.h>
#include <nm-utils.h>

#include "nm-l2tp-service.h"
#include "nm-ppp-status.h"

#ifndef DIST_VERSION
# define DIST_VERSION VERSION
#endif

#ifdef RUNSTATEDIR
# define RUNDIR RUNSTATEDIR
#else
# define RUNDIR "/var/run"
#endif

static gboolean debug = FALSE;

/********************************************************/
/* ppp plugin <-> l2tp-service object                   */
/********************************************************/

/* Have to have a separate objec to handle ppp plugin requests since
 * dbus-glib doesn't allow multiple interfaces registed on one GObject.
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
	void (*ip4_config) (NML2tpPppService *self, GHashTable *config_hash);
} NML2tpPppServiceClass;

GType nm_l2tp_ppp_service_get_type (void);

G_DEFINE_TYPE (NML2tpPppService, nm_l2tp_ppp_service, G_TYPE_OBJECT);

static gboolean impl_l2tp_service_need_secrets (NML2tpPppService *self,
                                                char **out_username,
                                                char **out_password,
                                                GError **err);

static gboolean impl_l2tp_service_set_state (NML2tpPppService *self,
                                             guint32 state,
                                             GError **err);

static gboolean impl_l2tp_service_set_ip4_config (NML2tpPppService *self,
                                                  GHashTable *config,
                                                  GError **err);

#include "nm-l2tp-pppd-service-glue.h"


#define NM_L2TP_PPP_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_L2TP_PPP_SERVICE, NML2tpPppServicePrivate))

typedef struct {
	char *username;
	char *domain;
	char *password;
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
			msg);
	return FALSE;
}

static gboolean
has_include_ipsec_secrets (const char *ipsec_secrets_file) {
	GIOChannel *channel;
	char *line = NULL;
	gboolean found = FALSE;

	channel = g_io_channel_new_file (ipsec_secrets_file, "r", NULL);
	if (!channel)
		return FALSE;

	while (!found && g_io_channel_read_line (channel, &line, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
		if (line) {
			g_strstrip (line);
			if (g_str_has_prefix (line, "include ipsec.d/ipsec.nm-l2tp.secrets")) {
				found = TRUE;
				break;
			}
			g_free (line);
		}
	}
	g_io_channel_shutdown (channel, FALSE, NULL);
	g_io_channel_unref (channel);

	return found;
}

static gboolean
check_is_libreswan (const char *path)
{
	const char *argv[] = { path, NULL };
	gboolean libreswan = FALSE;
	char *output = NULL;

	if (g_spawn_sync (NULL, (char **) argv, NULL, 0, NULL, NULL, &output, NULL, NULL, NULL)) {
		libreswan = output && strstr (output, " Libreswan ");
		g_free (output);
	}
	return libreswan;
}

static gboolean
check_is_strongswan (const char *path)
{
	const char *argv[] = { path, "--version", NULL };
	gboolean strongswan = FALSE;
	char *output = NULL;

	if (g_spawn_sync (NULL, (char **) argv, NULL, 0, NULL, NULL, &output, NULL, NULL, NULL)) {
		strongswan = output && strstr (output, " strongSwan ");
		g_free (output);
	}
	return strongswan;
}

static gboolean
_service_cache_credentials (NML2tpPppService *self,
							NMConnection *connection,
							GError **error)
{
	NML2tpPppServicePrivate *priv = NM_L2TP_PPP_SERVICE_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	const char *username, *password, *domain;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (!s_vpn) {
		return nm_l2tp_ipsec_error(error, _("Could not load NetworkManager connection settings."));
	}

	/* Username; try L2TP specific username first, then generic username */
	username = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER);
	if (!username || !*username) {
		username = nm_setting_vpn_get_user_name (s_vpn);
		if (!username || !*username) {
			return nm_l2tp_ipsec_error(error, _("Missing VPN username."));
		}
	}

	password = nm_setting_vpn_get_secret (s_vpn, NM_L2TP_KEY_PASSWORD);
	if (!password || !*password) {
		return nm_l2tp_ipsec_error(error, _("Missing or invalid VPN password."));
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
	DBusGConnection *bus;
	DBusGProxy *proxy;
	gboolean success = FALSE;
	guint result;

	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, error);
	if (!bus)
		return NULL;
	dbus_connection_set_change_sigpipe (TRUE);

	proxy = dbus_g_proxy_new_for_name (bus,
									   "org.freedesktop.DBus",
									   "/org/freedesktop/DBus",
									   "org.freedesktop.DBus");
	g_assert(proxy);
	if (dbus_g_proxy_call (proxy, "RequestName", error,
					   G_TYPE_STRING, NM_DBUS_SERVICE_L2TP_PPP,
					   G_TYPE_UINT, 0,
					   G_TYPE_INVALID,
					   G_TYPE_UINT, &result,
					   G_TYPE_INVALID)) {
		self = (NML2tpPppService *) g_object_new (NM_TYPE_L2TP_PPP_SERVICE, NULL);
		g_assert(self);
		dbus_g_connection_register_g_object (bus, NM_DBUS_PATH_L2TP_PPP, G_OBJECT (self));
		success = TRUE;
	} else {
		g_warning (_("Could not register D-Bus service name.  Message: %s"), (*error)->message);
	}
	g_object_unref (proxy);
	dbus_g_connection_unref (bus);
	return self;
}

static void
nm_l2tp_ppp_service_init (NML2tpPppService *self)
{
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
}

static void
nm_l2tp_ppp_service_class_init (NML2tpPppServiceClass *service_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (service_class);

	g_type_class_add_private (service_class, sizeof (NML2tpPppServicePrivate));

	/* virtual methods */
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
		              g_cclosure_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (service_class),
									 &dbus_glib_nm_l2tp_pppd_service_object_info);
}

static gboolean
impl_l2tp_service_need_secrets (NML2tpPppService *self,
                                char **out_username,
                                char **out_password,
                                GError **error)
{
	NML2tpPppServicePrivate *priv = NM_L2TP_PPP_SERVICE_GET_PRIVATE (self);

	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	if (!*priv->username || !*priv->password) {
		return nm_l2tp_ipsec_error(error, _("No cached credentials."));
	}

	/* Success */
	if (priv->domain && *priv->domain) {
		*out_username = g_strdup_printf ("%s\\%s", priv->domain, priv->username);
	} else {
		*out_username = g_strdup (priv->username);
	}
	*out_password = g_strdup (priv->password);
	return TRUE;
}

static gboolean
impl_l2tp_service_set_state (NML2tpPppService *self,
                             guint32 pppd_state,
                             GError **err)
{
	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);
	g_signal_emit (G_OBJECT (self), signals[PPP_STATE], 0, pppd_state);
	return TRUE;
}

static gboolean
impl_l2tp_service_set_ip4_config (NML2tpPppService *self,
                                  GHashTable *config_hash,
                                  GError **err)
{
	g_message (_("L2TP service (IP Config Get) reply received."));
	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	/* Just forward the pppd plugin config up to our superclass; no need to modify it */
	g_signal_emit (G_OBJECT (self), signals[IP4_CONFIG], 0, config_hash);

	return TRUE;
}


/********************************************************/
/* The VPN plugin service                               */
/********************************************************/

G_DEFINE_TYPE (NML2tpPlugin, nm_l2tp_plugin, NM_TYPE_VPN_PLUGIN);

typedef struct {
	GPid pid_l2tpd;
	gboolean ipsec_up;
	gboolean use_cert;
	guint32 ppp_timeout_handler;
	guint32 naddr;		/* We resolve GW addr before pass it to xl2tpd. network byte-order */
	char *saddr;
	NML2tpPppService *service;
	NMConnection *connection;
	char ipsec_binary_path[256];
	char *uuid;
	gboolean is_libreswan;
} NML2tpPluginPrivate;

#define NM_L2TP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_L2TP_PLUGIN, NML2tpPluginPrivate))

#define NM_L2TP_PPPD_PLUGIN PLUGINDIR "/nm-l2tp-pppd-plugin.so"
#define NM_L2TP_WAIT_IPSEC 10000 /* 10 seconds */
#define NM_L2TP_WAIT_PPPD 14000  /* 14 seconds */
#define L2TP_SERVICE_SECRET_TRIES "l2tp-service-secret-tries"

typedef struct {
	const char *name;
	GType type;
	gboolean required;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_L2TP_KEY_GATEWAY,           G_TYPE_STRING, TRUE },
	{ NM_L2TP_KEY_USER,              G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_USE_CERT,          G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_CERT_PUB,          G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_CERT_CA,           G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_CERT_KEY,          G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_DOMAIN,            G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_MRU,               G_TYPE_UINT, FALSE },
	{ NM_L2TP_KEY_MTU,               G_TYPE_UINT, FALSE },
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
	{ NM_L2TP_KEY_IPSEC_IKE,         G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_ESP,         G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_FORCEENCAPS, G_TYPE_BOOLEAN, FALSE },
	{ NULL }
};

static ValidProperty valid_secrets[] = {
	{ NM_L2TP_KEY_PASSWORD,          G_TYPE_STRING, FALSE },
	{ NULL,                          G_TYPE_NONE,   FALSE }
};

static gboolean
validate_gateway (const char *gateway)
{
	const char *p = gateway;

	if (!gateway || !gateway[0])
		return FALSE;

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
validate_gateway_id (const char *id)
{
	struct in_addr addr;

	if (!id || !id[0])
		return FALSE;

	if (id[0] == '@' || id[0] == '%')
		return TRUE;

	/* Ensure it's a valid IP address */
	return inet_aton (id, &addr);
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
			if (!strcmp (prop.name, NM_L2TP_KEY_IPSEC_PSK) ||
			    !strcmp (prop.name, NM_L2TP_KEY_CERT_PUB)  ||
			    !strcmp (prop.name, NM_L2TP_KEY_CERT_CA)  ||
			    !strcmp (prop.name, NM_L2TP_KEY_CERT_KEY) ||
			    !strcmp (prop.name, NM_L2TP_KEY_IPSEC_IKE) ||
			    !strcmp (prop.name, NM_L2TP_KEY_IPSEC_ESP) ||
			    !strcmp (prop.name, NM_L2TP_KEY_IPSEC_GROUP_NAME))
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
			if (   !strcmp (prop.name, NM_L2TP_KEY_IPSEC_GATEWAY_ID)
			    && !validate_gateway_id (value)) {
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
nm_l2tp_properties_validate (NMSettingVPN *s_vpn,
                             GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };
	int i;

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		return nm_l2tp_ipsec_error(error, _("No VPN configuration options."));
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
nm_l2tp_secrets_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		return nm_l2tp_ipsec_error(error, _("No VPN secrets!"));
	}

	return *error ? FALSE : TRUE;
}

static void
nm_l2tp_stop_ipsec (NML2tpPluginPrivate *priv);

static void
l2tpd_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NML2tpPlugin *plugin = NM_L2TP_PLUGIN (user_data);
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

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
		nm_l2tp_stop_ipsec (priv);
	}

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 16:
		/* hangup */
		// FIXME: better failure reason
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}

	nm_vpn_plugin_set_state (NM_VPN_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
}

static inline const char *
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
	nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT);

	return FALSE;
}

static gboolean
nm_l2tp_resolve_gateway (NML2tpPlugin *plugin,
						 NMSettingVPN *s_vpn,
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

static gboolean
str_to_int (const char *str, long int *out)
{
        long int tmp_int;

        if (!str)
                return FALSE;

        errno = 0;
        tmp_int = strtol (str, NULL, 10);
        if (errno == 0) {
                *out = tmp_int;
                return TRUE;
        }
        return FALSE;
}

static void
nm_l2tp_stop_ipsec (NML2tpPluginPrivate *priv)
{
	char cmdbuf[256];
	GPtrArray *whack_argv;
	int sys = 0;

	if (priv->is_libreswan) {
		whack_argv = g_ptr_array_new ();
		g_ptr_array_add (whack_argv, (gpointer) g_strdup (priv->ipsec_binary_path));
		g_ptr_array_add (whack_argv, (gpointer) g_strdup ("whack"));
		g_ptr_array_add (whack_argv, (gpointer) g_strdup ("--delete"));
		g_ptr_array_add (whack_argv, (gpointer) g_strdup ("--name"));
		g_ptr_array_add (whack_argv, (gpointer) g_strdup (priv->uuid));
		g_ptr_array_add (whack_argv, NULL);

		if (!g_spawn_sync (NULL, (char **) whack_argv->pdata, NULL,
			            0, NULL, NULL,
			            NULL,NULL,
			            NULL, NULL)) {
			free_args (whack_argv);
			return;
		}
	} else {
		snprintf (cmdbuf, sizeof(cmdbuf), "%s stop", priv->ipsec_binary_path);
		sys = system (cmdbuf);
	}

	g_message("ipsec shut down");
}

static gboolean
nm_l2tp_start_ipsec(NML2tpPlugin *plugin,
                            NMSettingVPN *s_vpn,
                            GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	char cmdbuf[256];
	char *output = NULL;
	int sys = 0, status, retry;
	int msec;
	gboolean rc = FALSE;
	gchar *argv[5];
	GPid pid_ipsec_up;
	pid_t wpid;

	if (priv->is_libreswan) {
		snprintf (cmdbuf, sizeof(cmdbuf), "%s auto --status > /dev/null", priv->ipsec_binary_path);
		sys = system (cmdbuf);
		if (sys == 1) {
			snprintf (cmdbuf, sizeof(cmdbuf), "%s start", priv->ipsec_binary_path);
			sys = system (cmdbuf);
			if (sys) {
				return nm_l2tp_ipsec_error (error, _("Could not start the ipsec service."));
			}
		} else {
			snprintf (cmdbuf, sizeof(cmdbuf), "%s restart", priv->ipsec_binary_path);
			sys = system (cmdbuf);
			if (sys) {
				return nm_l2tp_ipsec_error (error, _("Could not restart the ipsec service."));
			}
		}
		/* wait for Libreswan to get ready before performing an up operation */
		snprintf (cmdbuf, sizeof(cmdbuf), "%s auto --ready", priv->ipsec_binary_path);
		sys = system (cmdbuf);
		for (retry = 0; retry < 10 && sys != 0; retry++) {
			sleep (1);
			sys = system (cmdbuf);
		}
	} else {
		snprintf (cmdbuf, sizeof(cmdbuf), "%s status > /dev/null", priv->ipsec_binary_path);
		sys = system (cmdbuf);
		if (sys == 3) {
			snprintf (cmdbuf, sizeof(cmdbuf), "%s start "
				             " --conf "RUNDIR"/nm-l2tp-ipsec-%s.conf --debug",
				             priv->ipsec_binary_path, priv->uuid);
			sys = system (cmdbuf);
			if (sys) {
				return nm_l2tp_ipsec_error(error, _("Could not start the ipsec service."));
			}
		} else {
			snprintf (cmdbuf, sizeof(cmdbuf), "%s restart "
				             " --conf "RUNDIR"/nm-l2tp-ipsec-%s.conf --debug",
				             priv->ipsec_binary_path, priv->uuid);
			sys = system (cmdbuf);
			if (sys) {
				return nm_l2tp_ipsec_error(error, _("Could not restart the ipsec service."));
			}
		}
		/* wait for strongSwan to get ready before performing an up operation  */
		snprintf (cmdbuf, sizeof(cmdbuf), "%s rereadsecrets", priv->ipsec_binary_path);
		sys = system (cmdbuf);
		for (retry = 0; retry < 10 && sys != 0; retry++) {
			sleep (1);
			sys = system (cmdbuf);
		}
	}

	/* spawn ipsec script asynchronously as it sometimes doesn't exit */
	pid_ipsec_up = 0;
	if (!sys) {
		if (priv->is_libreswan) {
			snprintf (cmdbuf, sizeof(cmdbuf), "%s auto "
					 " --config "RUNDIR"/nm-l2tp-ipsec-%s.conf --verbose"
					 " --add '%s'", priv->ipsec_binary_path, priv->uuid, priv->uuid);
			sys = system(cmdbuf);
			if (!sys) {
				argv[0] = priv->ipsec_binary_path;
				argv[1] = "auto";
				argv[2] = "--up";
				argv[3] = priv->uuid;
				argv[4] = NULL;

				if (!g_spawn_async (NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
					NULL, NULL, &pid_ipsec_up, NULL)) {
					pid_ipsec_up = 0;
				} else {
					if (pid_ipsec_up)
						g_message ("Spawned ipsec auto --up script with PID %d.", pid_ipsec_up);
				}
			}
		} else {
			argv[0] = priv->ipsec_binary_path;
			argv[1] = "up";
			argv[2] = priv->uuid;
			argv[3] = NULL;

			if (!g_spawn_async (NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
				 NULL, NULL, &pid_ipsec_up, NULL)) {
				pid_ipsec_up = 0;
			} else {
				if (pid_ipsec_up)
					g_message ("Spawned ipsec up script with PID %d.", pid_ipsec_up);
			}
		}
	} else {
		g_warning (_("IPsec service is not ready."));
	}

	if (pid_ipsec_up > 0) {
		msec = 0;
		do {
			usleep (250000); /* 0.25 seconds */
			msec += 250;     /* 250 ms == 0.25 seconds */
			wpid = waitpid (pid_ipsec_up, &status, WNOHANG);
		} while (wpid == 0 && msec < NM_L2TP_WAIT_IPSEC);

		if (wpid <= 0) {
			if (kill (pid_ipsec_up, 0) == 0) {
				g_warning (_("Timeout trying to establish IPsec connection"));
				g_message ("Terminating ipsec script with PID %d.", pid_ipsec_up);
				kill (pid_ipsec_up, SIGKILL);
				/* Reap child */
				waitpid (pid_ipsec_up, NULL, 0);
			}
		} else if (wpid == pid_ipsec_up && WIFEXITED (status)) {
			if (!WEXITSTATUS (status)) {
				if (priv->is_libreswan) {
					rc = TRUE;
					g_message (_("Libreswan IPsec tunnel is up."));
				} else {
					/* Do not trust exit status of strongSwan 'ipsec up' command.
					   explictly check if connection is established.
					   strongSwan bug #1449.
					*/
					snprintf (cmdbuf, sizeof(cmdbuf), "%s status '%s'", priv->ipsec_binary_path, priv->uuid);
					if (g_spawn_command_line_sync(cmdbuf, &output, NULL, NULL, NULL)) {
						rc = output && strstr (output, "ESTABLISHED");
						g_free (output);
						if (rc) {
							g_message (_("strongSwan IPsec tunnel is up."));
						}
					}
				}
			}
		}
	}

	if (!rc) {
		if (!priv->is_libreswan) {
			snprintf (cmdbuf, sizeof(cmdbuf), "%s stop", priv->ipsec_binary_path);
			sys = system (cmdbuf);
		}
		g_warning(_("Could not establish IPsec tunnel."));
	}

	return rc;
}

static gboolean
nm_l2tp_start_l2tpd_binary (NML2tpPlugin *plugin,
                            NMSettingVPN *s_vpn,
                            GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	GPid pid;
	const char *l2tpd_binary;
	GPtrArray *l2tpd_argv;

	l2tpd_binary = nm_find_l2tpd ();
	if (!l2tpd_binary) {
		return nm_l2tp_ipsec_error(error, _("Could not find the xl2tpd binary."));
	}

	l2tpd_argv = g_ptr_array_new ();
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup (l2tpd_binary));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup ("-D"));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup ("-c"));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup_printf (RUNDIR"/nm-l2tp-xl2tpd-%s.conf", priv->uuid));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup ("-C"));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup_printf (RUNDIR"nm-l2tp-xl2tpd-control-%s", priv->uuid));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup ("-p"));
	g_ptr_array_add (l2tpd_argv, (gpointer) g_strdup_printf (RUNDIR"/nm-l2tp-xl2tpd-%s.pid", priv->uuid));
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

static gboolean
nm_l2tp_config_write (NML2tpPlugin *plugin,
					  NMSettingVPN *s_vpn,
					  GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	NMSettingIP4Config *s_ip4;
	const char *ipsec_secrets_file;
	const char *ipsec_conf_dir;
	const char *value;
	char *filename;
	char *psk_base64 = NULL;
	char errorbuf[128];
	gint fd = -1;
	FILE *fp;
	struct in_addr naddr;
	int port;
	int i;
	int errsv;
	gboolean l2tp_port_is_free;

	/* Setup runtime directory */
	if (g_mkdir_with_parents (RUNDIR, 0755) != 0) {
		errsv = errno;
		g_set_error (error,
			NM_VPN_PLUGIN_ERROR,
			NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			"Cannot create run-dir %s (%s)",
			RUNDIR, g_strerror (errsv));
		return FALSE;
	}

	/* Check that xl2tpd's default port 1701 is free */
	l2tp_port_is_free = is_port_free (1701);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_ENABLE);
	if (value && !strcmp(value,"yes")) {
		/*
		 * IPsec secrets
		 */
		ipsec_secrets_file = "/etc/ipsec.secrets";
		ipsec_conf_dir = "/etc/ipsec.d";
		if (!priv->is_libreswan) {
			if (g_file_test ("/etc/strongswan", G_FILE_TEST_IS_DIR)) {
				/* Fedora uses /etc/strongswan/ instead of /etc/ipsec/ */
				ipsec_secrets_file = "/etc/strongswan/ipsec.secrets";
				ipsec_conf_dir = "/etc/strongswan/ipsec.d";
			}

			/* if /etc/ipsec.secrets does not have "include ipsec.d/ipsec.nm-l2tp.secrets", add it */
			if (g_file_test (ipsec_secrets_file, G_FILE_TEST_EXISTS)) {
				if (!has_include_ipsec_secrets (ipsec_secrets_file)) {
					fd = open (ipsec_secrets_file, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);
					if (fd == -1) {
						snprintf (errorbuf, sizeof(errorbuf), _("Could not open %s"), ipsec_secrets_file);
						return nm_l2tp_ipsec_error(error, errorbuf);
					}
					fp = fdopen(fd, "a");
					fprintf(fp, "\n\ninclude ipsec.d/ipsec.nm-l2tp.secrets\n");
					fclose(fp);
					close(fd);
				}
			}
		}

		filename = g_strdup_printf ("%s/ipsec.nm-l2tp.secrets", ipsec_conf_dir);
		fd = open (filename, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
		g_free (filename);
		if (fd == -1) {
			snprintf (errorbuf, sizeof(errorbuf),
					  _("Could not write %s/ipsec.nm-l2tp.secrets"),
					  ipsec_conf_dir);
			return nm_l2tp_ipsec_error(error, errorbuf);
		}

		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_GATEWAY_ID);
		if (value) {
			if (priv->is_libreswan) {
				write_config_option (fd, "%%any ");
			}
			/* Only IP addresses and literal strings starting with 
			   @ or % are allowed as IDs with IKEv1 PSK */
			if (value[0] == '@' || value[0] == '%') {
				write_config_option (fd, "%s ", value);
			} else if (inet_pton(AF_INET, value, &naddr)) {
				write_config_option (fd, "%s ", value);
			} else {
				write_config_option (fd, "%%any ");
			}
		}

		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_PSK);
		if (!value) value="";
		psk_base64 = g_base64_encode ((const unsigned char *) value, strlen (value));
		write_config_option (fd, ": PSK 0s%s\n", psk_base64);
		close(fd);
		g_free (psk_base64);

		/*
		 * IPsec config
		 */
		filename = g_strdup_printf (RUNDIR"/nm-l2tp-ipsec-%s.conf", priv->uuid);
		fd = open (filename, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
		g_free (filename);
		if (fd == -1) {
			return nm_l2tp_ipsec_error(error, _("Could not write ipsec config."));
		}

		write_config_option (fd, "conn %s\n", priv->uuid);
		write_config_option (fd, "  auto=add\n");
		write_config_option (fd, "  type=transport\n");

		write_config_option (fd, "  authby=secret\n");
		write_config_option (fd, "  left=%%defaultroute\n");
		if (l2tp_port_is_free) {
			write_config_option (fd, "  leftprotoport=udp/l2tp\n");
		}

		write_config_option (fd, "  right=%s\n", priv->saddr);
		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_GATEWAY_ID);
		if (value) {
			write_config_option (fd, "  rightid=%s\n", value);
		} else {
			write_config_option (fd, "  rightid=%%any\n");
		}
		write_config_option (fd, "  rightprotoport=udp/l2tp\n");

		if (priv->is_libreswan) {
			write_config_option (fd, "  ikev2=never\n");
		} else {
			write_config_option (fd, "  keyexchange=ikev1\n");
		}

		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_IKE);
		if (value) {
			write_config_option (fd, "  ike=%s\n", value);
		} else if (!priv->is_libreswan) {
			write_config_option (fd, "  ike=aes128-sha1-modp2048,3des-sha1-modp1536,3des-sha1-modp1024\n");
		}

		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_ESP);
		if (value) {
			write_config_option (fd, "  esp=%s\n", value);
		} else if (!priv->is_libreswan) {
			write_config_option (fd, "  esp=aes128-sha1,3des-sha1\n");
		}

		write_config_option (fd, "  keyingtries=%%forever\n");
		if (priv->is_libreswan) {
			write_config_option (fd, "  pfs=no\n");
		}

		value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_FORCEENCAPS);
		if(value)write_config_option (fd, "  forceencaps=%s\n", value);

		close(fd);

	}

	/*
	 * L2TP options
	 */

	/* xl2tpd config */
	filename = g_strdup_printf (RUNDIR"/nm-l2tp-xl2tpd-%s.conf", priv->uuid);
	fd = open (filename, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	g_free (filename);

	if (fd == -1) {
		return nm_l2tp_ipsec_error(error, _("Could not write xl2tpd config."));
	}

	write_config_option (fd, "[global]\n");
	write_config_option (fd, "access control = yes\n");

	/* If xl2tpd's default port 1701 is busy, use 0 (ephemeral random port) */
	port = 1701;
	if (!l2tp_port_is_free){
		port = 0;
		g_warning("L2TP port 1701 is busy, using ephemeral.");
	}
	write_config_option (fd, "port = %d\n", port);
	if (debug){
		/* write_config_option (fd, "debug network = yes\n"); */
		write_config_option (fd, "debug state = yes\n");
		write_config_option (fd, "debug tunnel = yes\n");
		write_config_option (fd, "debug avp = yes\n");
	}

	write_config_option (fd, "[lac l2tp]\n");

	/* value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_GATEWAY); */
	write_config_option (fd, "lns = %s\n", priv->saddr);

	/* Username; try L2TP specific username first, then generic username */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER);
	if (!value || !*value)
		value = nm_setting_vpn_get_user_name (s_vpn);
	if (!value || !*value) {
		write_config_option (fd, "name = %s\n", value);
	}

	if (debug)
		write_config_option (fd, "ppp debug = yes\n");
	write_config_option (fd, "pppoptfile = "RUNDIR"/nm-l2tp-ppp-options-%s\n", priv->uuid);
	write_config_option (fd, "autodial = yes\n");
	write_config_option (fd, "tunnel rws = 8\n");
	write_config_option (fd, "tx bps = 100000000\n");
	write_config_option (fd, "rx bps = 100000000\n");

	close(fd);

	/* PPP options */

	filename = g_strdup_printf (RUNDIR"/nm-l2tp-ppp-options-%s", priv->uuid);
	fd = open (filename, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	g_free (filename);

	if (fd == -1) {
		return nm_l2tp_ipsec_error(error, _("Could not write ppp options."));
	}

	if (debug)
		write_config_option (fd, "debug\n");

	write_config_option (fd, "ipparam nm-l2tp-service-%s\n", priv->uuid);

	write_config_option (fd, "nodetach\n");
	/* revisit - xl2tpd-1.3.7 generates an unrecognized option 'lock' error.
	   but with xl2tpd-1.3.6, pppd wasn't creating a lock file under /var/run/lock/ anyway.
	write_config_option (fd, "lock\n");
	*/

	s_ip4 = nm_connection_get_setting_ip4_config (priv->connection);
	if (!nm_setting_ip4_config_get_ignore_auto_dns (s_ip4)) {
		write_config_option (fd, "usepeerdns\n");
	}

	write_config_option (fd, "noipdefault\n");
	write_config_option (fd, "nodefaultroute\n");

	/* Don't need to auth the L2TP server */
	write_config_option (fd, "noauth\n");

	/* pppd and xl2tpd on Linux require this option to support Android and iOS clients,
	   and pppd on Linux clients won't work without the same option */
	write_config_option (fd, "noccp\n");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER);
	if (!value || !*value)
		value = nm_setting_vpn_get_user_name (s_vpn);
	if (!value || !*value) {
		write_config_option (fd, "name %s\n", value);
	}

	for(i=0; ppp_options[i].name; i++){
		value = nm_setting_vpn_get_data_item (s_vpn, ppp_options[i].name);
		if (value && !strcmp (value, "yes"))
			write_config_option (fd, ppp_options[i].write_to_config);
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_LCP_ECHO_FAILURE);
	if (value && *value) {
		long int tmp_int;

		/* Convert to integer and then back to string for security's sake
		 * because strtol ignores some leading and trailing characters.
		 */
		if (str_to_int (value, &tmp_int)) {
			write_config_option (fd, "lcp-echo-failure %ld\n", tmp_int);
		} else {
			g_warning("failed to convert lcp-echo-failure value '%s'", value);
		}
	} else {
		write_config_option (fd, "lcp-echo-failure 0\n");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_LCP_ECHO_INTERVAL);
	if (value && *value) {
		long int tmp_int;
		if (str_to_int (value, &tmp_int)) {
			write_config_option (fd, "lcp-echo-interval %ld\n", tmp_int);
		} else {
			g_warning("failed to convert lcp-echo-interval value '%s'", value);
		}
	} else {
		write_config_option (fd, "lcp-echo-interval 0\n");
	}

	write_config_option (fd, "plugin %s\n", NM_L2TP_PPPD_PLUGIN);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_MRU);
	if (value) {
		write_config_option (fd, "mru %s\n", value);
	} else {
		write_config_option (fd, "mru 1400\n");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_MTU);
	if (value) {
		write_config_option (fd, "mtu %s\n", value);
	} else {
		/* Default MTU to 1400, which is also what Microsoft Windows uses */
		write_config_option (fd, "mtu 1400\n");
	}

	if (priv && priv->use_cert) {
		write_config_option (fd, "cert \"%s\"\n", nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_CERT_PUB));
		write_config_option (fd, "ca \"%s\"\n", nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_CERT_CA));
		write_config_option (fd, "key \"%s\"\n", nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_CERT_KEY));
	}

	close(fd);

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
	NMVPNServiceState plugin_state = nm_vpn_plugin_get_state (NM_VPN_PLUGIN (plugin));

	switch (ppp_state) {
	case NM_PPP_STATUS_DEAD:
	case NM_PPP_STATUS_DISCONNECT:
		if (plugin_state == NM_VPN_SERVICE_STATE_STARTED)
			nm_vpn_plugin_disconnect (NM_VPN_PLUGIN (plugin), NULL);
		else if (plugin_state == NM_VPN_SERVICE_STATE_STARTING)
			nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}
}

static void
nm_gvalue_destroy (gpointer data)
{
	g_value_unset ((GValue *) data);
	g_slice_free (GValue, data);
}

static GValue *
nm_gvalue_dup (const GValue *value)
{
	GValue *value_dup;

	value_dup = g_slice_new0 (GValue);
	g_value_init (value_dup, G_VALUE_TYPE (value));
	g_value_copy (value, value_dup);

	return value_dup;
}

static void
copy_hash (gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_insert ((GHashTable *) user_data, g_strdup (key), nm_gvalue_dup ((GValue *) value));
}

static void
service_ip4_config_cb (NML2tpPppService *service,
                       GHashTable *config_hash,
                       NMVPNPlugin *plugin)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	GHashTable *hash;
	GValue *value;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, nm_gvalue_destroy);
	g_hash_table_foreach (config_hash, copy_hash, hash);

	/* Insert the external VPN gateway into the table, which the pppd plugin
	 * simply doesn't know about.
	 */
	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_UINT);
	g_value_set_uint (value, priv->naddr);
	g_hash_table_insert (hash, g_strdup (NM_L2TP_KEY_GATEWAY), value);

	nm_vpn_plugin_set_ip4_config (plugin, hash);

	g_hash_table_destroy (hash);
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVPN *s_vpn;
	const char *value;
	const char *uuid;

	if (getenv ("NM_PPP_DUMP_CONNECTION") || debug)
		nm_connection_dump (connection);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_ENABLE);
	g_message(_("ipsec enable flag: %s"), value?value:"(null)");
	priv->is_libreswan = TRUE;
	if(value && !strcmp(value,"yes")) {
		if (!(value=nm_find_ipsec ())) {
			return nm_l2tp_ipsec_error (error, _("Could not find the ipsec binary. Is Libreswan or strongSwan installed?"));
		}

		strncpy (priv->ipsec_binary_path, value, sizeof(priv->ipsec_binary_path) - 1);
		priv->is_libreswan = check_is_libreswan (priv->ipsec_binary_path);
		if (!priv->is_libreswan && !check_is_strongswan (priv->ipsec_binary_path)) {
			return nm_l2tp_ipsec_error (error, _("Neither Libreswan nor strongSwan were found."));
		}
	}

	if (!nm_l2tp_properties_validate (s_vpn, error))
		return FALSE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USE_CERT);
	if (value && !strcmp (value,"yes"))
		priv->use_cert = TRUE;

	if (!priv->use_cert && !nm_l2tp_secrets_validate (s_vpn, error))
		return FALSE;

	g_clear_object (&priv->service);
	g_clear_object (&priv->connection);

	/* Start our pppd plugin helper service */
	priv->service = nm_l2tp_ppp_service_new (connection, error);
	if (!priv->service) {
		return nm_l2tp_ipsec_error(error, _("Could not start pppd plugin helper service."));
	}

	priv->connection = g_object_ref (connection);

	uuid = nm_connection_get_uuid (priv->connection);
	if (!(uuid && *uuid)) {
		return nm_l2tp_ipsec_error(error, _("could not retrieve connection UUID"));
	}

	g_free (priv->uuid);
	priv->uuid = g_strdup (uuid);

	g_signal_connect (G_OBJECT (priv->service), "plugin-alive", G_CALLBACK (service_plugin_alive_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ppp-state", G_CALLBACK (service_ppp_state_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ip4-config", G_CALLBACK (service_ip4_config_cb), plugin);

	/* Cache the username and password so we can relay the secrets to the pppd
	 * plugin when it asks for them.
	 */
	if (!priv->use_cert && !_service_cache_credentials (priv->service, connection, error))
		return FALSE;

	if (!nm_l2tp_resolve_gateway (NM_L2TP_PLUGIN (plugin), s_vpn, error))
		return FALSE;

	if (!nm_l2tp_config_write (NM_L2TP_PLUGIN (plugin), s_vpn, error))
		return FALSE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_ENABLE);
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
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSetting *s_vpn;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
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
real_disconnect (NMVPNPlugin   *plugin,
			  GError       **err)
{
	char *filename;

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
		nm_l2tp_stop_ipsec (priv);
	}

	if (priv->connection) {
		g_object_unref (priv->connection);
		priv->connection = NULL;
	}

	if (priv->service) {
		g_object_unref (priv->service);
		priv->service = NULL;
	}

	if (!debug) {
		/* Cleaning up config files */
		filename = g_strdup_printf (RUNDIR"/nm-l2tp-xl2tpd-%s.conf", priv->uuid);
		unlink(filename);
		g_free(filename);

		filename = g_strdup_printf (RUNDIR"/nm-l2tp-ppp-options-%s", priv->uuid);
		unlink(filename);
		g_free(filename);

		filename = g_strdup_printf (RUNDIR"/nm-l2tp-xl2tpd-control-%s", priv->uuid);
		unlink(filename);
		g_free(filename);

		filename = g_strdup_printf (RUNDIR"/nm-l2tp-xl2tpd-%s.pid", priv->uuid);
		unlink(filename);
		g_free(filename);

		filename = g_strdup_printf (RUNDIR"/nm-l2tp-ipsec-%s.conf", priv->uuid);
		unlink(filename);
		g_free(filename);

		filename = g_strdup_printf ("/etc/ipsec.d/ipsec.nm-l2tp.secrets");
		unlink(filename);
		g_free(filename);

		filename = g_strdup_printf ("/etc/strongswan/ipsec.d/ipsec.nm-l2tp.secrets");
		unlink(filename);
		g_free(filename);
	}

	return TRUE;
}

static void
state_changed_cb (GObject *object, NMVPNServiceState state, gpointer user_data)
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
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (l2tp_class);

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
	                       NM_VPN_PLUGIN_DBUS_SERVICE_NAME,
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
	    _("nm-l2tp-service provides L2TP VPN capability with optional IPsec support to NetworkManager."));

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
