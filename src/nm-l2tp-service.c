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

#include "nm-default.h"

#include "nm-l2tp-service.h"

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

#include "nm-ppp-status.h"
#include "nm-l2tp-pppd-service-dbus.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static struct {
	gboolean debug;
	int log_level;
} gl/*lobal*/;

static void nm_l2tp_plugin_initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NML2tpPlugin, nm_l2tp_plugin, NM_TYPE_VPN_SERVICE_PLUGIN,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_l2tp_plugin_initable_iface_init));

typedef struct {
	GPid pid_l2tpd;
	gboolean ipsec_up;
	gboolean use_cert;
	guint32 ipsec_timeout_handler;
	guint32 ppp_timeout_handler;
	NMConnection *connection;
	NMDBusL2tpPpp *dbus_skeleton;
	char ipsec_binary_path[256];
	gboolean is_libreswan;

	/* IP of L2TP gateway in numeric and string format */
	guint32 naddr;
	char *saddr;
} NML2tpPluginPrivate;

#define NM_L2TP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_L2TP_PLUGIN, NML2tpPluginPrivate))

#define NM_L2TP_PPPD_PLUGIN PLUGINDIR "/nm-l2tp-pppd-plugin.so"
#define NM_L2TP_WAIT_IPSEC 10000 /* 10 seconds */
#define NM_L2TP_WAIT_PPPD 14000  /* 14 seconds */
#define L2TP_SERVICE_SECRET_TRIES "l2tp-service-secret-tries"

/*****************************************************************************/

#define _NMLOG(level, ...) \
    G_STMT_START { \
         if (gl.log_level >= (level)) { \
              g_print ("nm-l2tp[%ld] %-7s " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
                       (long) getpid (), \
                       nm_utils_syslog_to_str (level) \
                       _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
         } \
    } G_STMT_END

static gboolean
_LOGD_enabled (void)
{
	return gl.log_level >= LOG_INFO;
}

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

typedef struct {
	const char *name;
	GType type;
	bool required:1;
} ValidProperty;

static const ValidProperty valid_properties[] = {
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
	{ NM_L2TP_KEY_UNIT_NUM,          G_TYPE_UINT, FALSE },
	{ NM_L2TP_KEY_PASSWORD"-flags",  G_TYPE_UINT, FALSE },
	{ NM_L2TP_KEY_IPSEC_ENABLE,      G_TYPE_BOOLEAN, FALSE },
	{ NM_L2TP_KEY_IPSEC_GATEWAY_ID,  G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_GROUP_NAME,  G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_PSK,         G_TYPE_STRING, FALSE },
	{ NM_L2TP_KEY_IPSEC_FORCEENCAPS, G_TYPE_BOOLEAN, FALSE },
	{ NULL }
};

static ValidProperty valid_secrets[] = {
	{ NM_L2TP_KEY_PASSWORD,          G_TYPE_STRING, FALSE },
	{ NULL }
};

static gboolean
nm_l2tp_ipsec_error(GError **error, const char *msg) {
	g_set_error_literal (error,
			NM_VPN_PLUGIN_ERROR,
			NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
			_(msg));
	return FALSE;
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
validate_gateway (const char *gateway)
{
	const char *p = gateway;

	if (!gateway || !strlen (gateway))
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
	const ValidProperty *table;
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

	for (i = 0; info->table[i].name; i++) {
		const ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			if (!strcmp (prop.name, NM_L2TP_KEY_IPSEC_PSK) ||
			    !strcmp (prop.name, NM_L2TP_KEY_CERT_PUB)  ||
			    !strcmp (prop.name, NM_L2TP_KEY_CERT_CA)  ||
			    !strcmp (prop.name, NM_L2TP_KEY_CERT_KEY))
				return; /* valid */

			if (   !strcmp (prop.name, NM_L2TP_KEY_GATEWAY)
			    && !validate_gateway (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid gateway '%s'"),
				             key);
				return; /* valid */
			}

			if (   !strcmp (prop.name, NM_L2TP_KEY_IPSEC_GROUP_NAME)
			    && !validate_ipsec_id (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid ipsec-group-name '%s'"),
				             key);
				return; /* valid */
			}

			if (   !strcmp (prop.name, NM_L2TP_KEY_IPSEC_GATEWAY_ID)
			    && !validate_ipsec_id (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid ipsec-gateway-id '%s'"),
				             key);
				return; /* valid */
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
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN configuration options."));
		return FALSE;
	}

	if (*error)
		return FALSE;

	/* Ensure required properties exist */
	for (i = 0; valid_properties[i].name; i++) {
		const ValidProperty prop = valid_properties[i];
		const char *value;

		if (!prop.required)
			continue;

		value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
		if (!value || !strlen (value)) {
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
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN secrets!"));
		return FALSE;
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
	pid_t my_pid = getpid ();
	char *filename;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			_LOGW ("xl2tpd exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		_LOGW ("xl2tpd stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		_LOGW ("xl2tpd died with signal %d", WTERMSIG (status));
	else
		_LOGW ("xl2tpd died from an unknown cause");

	/* Reap child if needed. */
	waitpid (priv->pid_l2tpd, NULL, WNOHANG);
	priv->pid_l2tpd = 0;

	if(priv->ipsec_up) {
		nm_l2tp_stop_ipsec (priv);
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
ipsec_timed_out (gpointer user_data)
{
	NML2tpPlugin *plugin = NM_L2TP_PLUGIN (user_data);
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);

	_LOGW ("Timeout trying to establish IPsec connection");
	nm_l2tp_stop_ipsec(priv);
	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);


	return FALSE;
}

static gboolean
pppd_timed_out (gpointer user_data)
{
	NML2tpPlugin *plugin = NM_L2TP_PLUGIN (user_data);

	_LOGW ("Looks like pppd didn't initialize our dbus module");
	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);

	return FALSE;
}

static void
free_l2tpd_args (GPtrArray *args)
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
		_LOGW ("Can-not create new test socket");
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
                      NMSettingVpn *s_vpn,
                      GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	char *filename;
	pid_t pid = getpid ();
	const char *value;
	gint conf_fd = -1;
	gint ipsec_fd = -1;
	gint pppopt_fd = -1;
	struct in_addr naddr;
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

	write_config_option (ipsec_fd, 		"conn nm-ipsec-l2tp-%d\n", pid);
	write_config_option (ipsec_fd, 		"  auto=add\n"
						"  type=transport\n");

	write_config_option (ipsec_fd,	"  authby=secret\n"
						"  keyingtries=0\n"
						"  left=%%defaultroute\n"
						"  leftprotoport=udp/l2tp\n"
						"  rightprotoport=udp/l2tp\n");
	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_GROUP_NAME);
	if (value) {
		if (priv->is_libreswan) {
			if(inet_pton(AF_INET, value, &naddr)) {
				write_config_option (ipsec_fd, "  leftid=%s\n", value);
			} else {
				/* @ prefix prevents leftid being resolved to an IP address */
				write_config_option (ipsec_fd, "  leftid=@%s\n", value);
			}
		} else {
			write_config_option (ipsec_fd, "  leftid=%s\n", value);
		}
	}
	write_config_option (ipsec_fd, "  right=%s\n", priv->saddr);
	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_GATEWAY_ID);
	if (value) {
		if (priv->is_libreswan) {
			if(inet_pton(AF_INET, value, &naddr)) {
				write_config_option (ipsec_fd, "  rightid=%s\n", value);
			} else {
				/* @ prefix prevents rightid being resolved to an IP address */
				write_config_option (ipsec_fd, "  rightid=@%s\n", value);
			}
		} else {
			write_config_option (ipsec_fd, "  rightid=%s\n", value);
		}
	} else {
		write_config_option (ipsec_fd, "  rightid=%%any\n");
	}

	if (priv->is_libreswan) {
		write_config_option (ipsec_fd, "  pfs=no\n");
	} else {
		write_config_option (ipsec_fd, "  esp=aes128-sha1,3des-sha1\n");
		write_config_option (ipsec_fd, "  ike=aes128-sha1-modp2048,3des-sha1-modp1536,3des-sha1-modp1024\n");
		write_config_option (ipsec_fd, "  keyexchange=ikev1\n");
	}
	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_FORCEENCAPS);
	if(value)write_config_option (ipsec_fd, "  forceencaps=%s\n", value);

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
		_LOGW ("Port 1701 is busy, use ephemeral.");
	}
	write_config_option (conf_fd, "port = %d\n", port);
	if (_LOGD_enabled ()){
		/* write_config_option (conf_fd, "debug network = yes\n"); */
		write_config_option (conf_fd, "debug state = yes\n");
		write_config_option (conf_fd, "debug tunnel = yes\n");
		write_config_option (conf_fd, "debug avp = yes\n");
	}

	write_config_option (conf_fd, "[lac l2tp]\n");

	/* value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_GATEWAY); */
	write_config_option (conf_fd, "lns = %s\n", priv->saddr);

	/* Username; try L2TP specific username first, then generic username */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER);
	if (!value || !*value)
		value = nm_setting_vpn_get_user_name (s_vpn);
	if (!value || !*value) {
		write_config_option (conf_fd, "name = %s\n", value);
	}

	if (_LOGD_enabled ())
		write_config_option (conf_fd, "ppp debug = yes\n");
	write_config_option (conf_fd, "pppoptfile = /var/run/nm-ppp-options.xl2tpd.%d\n", pid);
	write_config_option (conf_fd, "autodial = yes\n");
	write_config_option (conf_fd, "tunnel rws = 8\n");
	write_config_option (conf_fd, "tx bps = 100000000\n");
	write_config_option (conf_fd, "rx bps = 100000000\n");

	/* PPP options */
	if (_LOGD_enabled ())
		write_config_option (pppopt_fd, "debug\n");

	write_config_option (pppopt_fd, "ipparam nm-l2tp-service-%d\n", pid);

	write_config_option (pppopt_fd, "nodetach\n");
	/* revisit - xl2tpd-1.3.7 generates an unrecognized option 'lock' error.
	   but with xl2tpd-1.3.6, pppd wasn't creating a lock file under /var/run/lock/ anyway.
	write_config_option (pppopt_fd, "lock\n");
	*/
	write_config_option (pppopt_fd, "usepeerdns\n");
	write_config_option (pppopt_fd, "noipdefault\n");
	write_config_option (pppopt_fd, "nodefaultroute\n");

	/* Don't need to auth the L2TP server */
	write_config_option (pppopt_fd, "noauth\n");

	/* pppd and xl2tpd on Linux require this option to support Android and iOS clients,
	   and pppd on Linux clients won't work without the same option */
	write_config_option (pppopt_fd, "noccp\n");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER);
	if (!value || !*value)
		value = nm_setting_vpn_get_user_name (s_vpn);
	if (!value || !*value) {
		write_config_option (pppopt_fd, "name %s\n", value);
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
		if (str_to_int (value, &tmp_int)) {
			write_config_option (pppopt_fd, "lcp-echo-failure %ld\n", tmp_int);
		} else {
			_LOGW ("failed to convert lcp-echo-failure value '%s'", value);
		}
	} else {
		write_config_option (pppopt_fd, "lcp-echo-failure 0\n");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_LCP_ECHO_INTERVAL);
	if (value && *value) {
		long int tmp_int;
		if (str_to_int (value, &tmp_int)) {
			write_config_option (pppopt_fd, "lcp-echo-interval %ld\n", tmp_int);
		} else {
			_LOGW ("failed to convert lcp-echo-interval value '%s'", value);
		}
	} else {
		write_config_option (pppopt_fd, "lcp-echo-interval 0\n");
	}

	write_config_option (pppopt_fd, "plugin %s\n", NM_L2TP_PPPD_PLUGIN);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_MRU);
	if (value) {
		write_config_option (pppopt_fd, "mru %s\n", value);
	} else {
		write_config_option (pppopt_fd, "mru 1400\n");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_MTU);
	if (value) {
		write_config_option (pppopt_fd, "mtu %s\n", value);
	} else {
		/* Default MTU to 1400, which is also what Microsoft Windows uses */
		write_config_option (pppopt_fd, "mtu 1400\n");
	}

	/*
	if (priv && priv->use_cert) {
		write_config_option (pppopt_fd, "cert \"%s\"\n", nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_CERT_PUB));
		write_config_option (pppopt_fd, "ca \"%s\"\n", nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_CERT_CA));
		write_config_option (pppopt_fd, "key \"%s\"\n", nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_CERT_KEY));
	}
	*/

	close(ipsec_fd);
	close(conf_fd);
	close(pppopt_fd);

	return TRUE;
}

static void
nm_l2tp_stop_ipsec (NML2tpPluginPrivate *priv)
{
	char cmdbuf[256];
	char session_name[128];
	GPtrArray *whack_argv;
	int sys = 0;

	if (priv->is_libreswan) {
		snprintf (session_name, sizeof(session_name), "nm-ipsec-l2tp-%d", getpid ());
		whack_argv = g_ptr_array_new ();
		g_ptr_array_add (whack_argv, (gpointer) g_strdup (priv->ipsec_binary_path));
		g_ptr_array_add (whack_argv, (gpointer) g_strdup ("whack"));
		g_ptr_array_add (whack_argv, (gpointer) g_strdup ("--delete"));
		g_ptr_array_add (whack_argv, (gpointer) g_strdup ("--name"));
		g_ptr_array_add (whack_argv, (gpointer) g_strdup (session_name));
		g_ptr_array_add (whack_argv, NULL);

		if (!g_spawn_sync (NULL, (char **) whack_argv->pdata, NULL,
			            0, NULL, NULL,
			            NULL,NULL,
			            NULL, NULL)) {
			free_l2tpd_args (whack_argv);
			return;
		}
	} else {
		snprintf (cmdbuf, sizeof(cmdbuf), "%s stop nm-ipsec-l2tp-%d", priv->ipsec_binary_path, getpid ());
		sys = system (cmdbuf);
	}

	g_message("ipsec shut down");
}

static gboolean
nm_l2tp_start_ipsec(NML2tpPlugin *plugin,
                            NMSettingVpn *s_vpn,
                            GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	const char *value;
	const char *secrets;
	char tmp_secrets[128];
	char session_name[128];
	char cmdbuf[256];
	char *output = NULL;
	struct in_addr naddr;
	int sys = 0, retry;
	int fd;
	FILE *fp;
	gboolean rc = FALSE;

	snprintf(session_name, sizeof(session_name), "nm-ipsec-l2tp-%d", getpid());

	if (priv->is_libreswan) {

		snprintf (cmdbuf, sizeof(cmdbuf), "%s auto --status > /dev/null", priv->ipsec_binary_path);
		sys = system (cmdbuf);
		if (sys) {
			snprintf (cmdbuf, sizeof(cmdbuf), "%s _stackmanager start", priv->ipsec_binary_path);
			sys = system (cmdbuf);
			if (sys) {
				return nm_l2tp_ipsec_error (error, "Could not load required IPsec kernel stack.");
			}
		}

		snprintf (cmdbuf, sizeof(cmdbuf), "%s restart", priv->ipsec_binary_path);
		sys = system (cmdbuf);
		if (sys) {
			return nm_l2tp_ipsec_error (error, "Could not restart the ipsec service.");
		}

		snprintf (cmdbuf, sizeof(cmdbuf), "%s auto --ready", priv->ipsec_binary_path);
		sys = system (cmdbuf);
		for (retry = 0; retry < 10 && sys != 0; retry++) {
			sleep (1); // wait for ipsec to get ready
			sys = system (cmdbuf);
		}
		if (sys) {
			return nm_l2tp_ipsec_error (error, "Could not talk to pluto the IKE daemon.");
		}

	} else {
		snprintf (cmdbuf, sizeof(cmdbuf), "%s restart "
		                 " --conf /var/run/nm-ipsec-l2tp.%d/ipsec.conf --debug",
		                 priv->ipsec_binary_path, getpid ());
		sys = system (cmdbuf);
		if (sys) {
			return nm_l2tp_ipsec_error(error, "Could not restart the ipsec service.");
		}
	}


	/* the way this works is sadly very messy
	   we replace the user's /etc/ipsec.secrets file
	   we ask strongSwan/Libreswan to reload the secrets,
	   we whack in our connection,
	   we then replace the secrets and ask strongSwan/Libreswan to reload them
	*/
	secrets = "/etc/ipsec.secrets";
	if (!priv->is_libreswan) {
		if (g_file_test ("/etc/strongswan/ipsec.secrets", G_FILE_TEST_EXISTS)) {
			secrets = "/etc/strongswan/ipsec.secrets";
		}
	}
	snprintf(tmp_secrets, sizeof(tmp_secrets), "%s.%d", secrets, getpid());
	if(-1==rename(secrets, tmp_secrets) && errno != EEXIST) {
		return nm_l2tp_ipsec_error(error, "Could not save existing /etc/ipsec.secrets file.");
	}

	fp = NULL;
	if ((fd = open(secrets, O_CREAT | O_EXCL | O_WRONLY, 0600)) >= 0) {
		if (NULL == (fp = fdopen(fd, "w"))) close(fd);
	}
	if (NULL == fp) {
		rename(tmp_secrets, secrets);
		return nm_l2tp_ipsec_error(error, "Could not write /etc/ipsec.secrets file.");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_PSK);
	if(!value)value="";
	fprintf(fp, ": PSK \"%s\"\n",value);
	fclose(fp);
	close(fd);

	if (priv->is_libreswan) {
		snprintf (cmdbuf, sizeof(cmdbuf), "%s auto --rereadsecrets", priv->ipsec_binary_path);
	} else {
		snprintf (cmdbuf, sizeof(cmdbuf), "%s rereadsecrets", priv->ipsec_binary_path);
	}
	sys = 1;
	for (retry = 0; retry < 10 && sys != 0; retry++) {
		sys = system (cmdbuf);
		if (sys != 0)
			sleep (1); // wait for strongSwan to get ready
	}

	if (!sys) {
		priv->ipsec_timeout_handler = g_timeout_add (NM_L2TP_WAIT_IPSEC, ipsec_timed_out, plugin);
		if (priv->is_libreswan) {
			snprintf (cmdbuf, sizeof(cmdbuf), "%s auto "
					 " --config /var/run/nm-ipsec-l2tp.%d/ipsec.conf --verbose"
					 " --add '%s'", priv->ipsec_binary_path, getpid (), session_name);
			sys = system(cmdbuf);
			if (!sys) {
				snprintf(cmdbuf, sizeof(cmdbuf), "%s auto --up '%s'",
						 priv->ipsec_binary_path, session_name);
				sys = system (cmdbuf);
				if (!sys) {
					rc = TRUE;
					_LOGI ("Libreswan ready for action.");
				} else {
					_LOGW ("Could not establish IPsec tunnel.");
				}
			} else {
				_LOGW ("Could not establish IPsec tunnel.");
			}

		} else {
			snprintf (cmdbuf, sizeof(cmdbuf), "%s up '%s'", priv->ipsec_binary_path, session_name);
			sys = system (cmdbuf);
			if (!sys) {
				// Do not trust exit status of strongSwan 'ipsec up' command.
				// explictly check if connection is established.
				snprintf (cmdbuf, sizeof(cmdbuf), "%s status '%s'", priv->ipsec_binary_path, session_name);
				if (g_spawn_command_line_sync(cmdbuf, &output, NULL, NULL, NULL)) {
					rc = output && strstr (output, "ESTABLISHED");
					g_free (output);
					if (rc) {
						_LOGI ("strongSwan ready for action.");
					} else {
						_LOGW ("Could not establish IPsec tunnel.");
					}
				}
			} else {
				_LOGW ("Could not establish IPsec tunnel.");
			}
		}

		g_source_remove (priv->ipsec_timeout_handler);
		priv->ipsec_timeout_handler = 0;

	} else {
		_LOGW ("Could not load new IPsec secret.");
	}

	snprintf (cmdbuf, sizeof(cmdbuf), "%s secrets", priv->ipsec_binary_path);
	if (rename(tmp_secrets, secrets) ||
			system (cmdbuf)) {
		_LOGW ("Could not restore saved %s from %s.", secrets, tmp_secrets);
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
		g_ptr_array_free (l2tpd_argv, TRUE);
		return FALSE;
	}
	free_l2tpd_args (l2tpd_argv);

	g_message ("xl2tpd started with pid %d", pid);

	NM_L2TP_PLUGIN_GET_PRIVATE (plugin)->pid_l2tpd = pid;
	g_child_watch_add (pid, l2tpd_watch_cb, plugin);

	priv->ppp_timeout_handler = g_timeout_add (NM_L2TP_WAIT_PPPD, pppd_timed_out, plugin);

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

static gboolean
handle_need_secrets (NMDBusL2tpPpp *object,
                     GDBusMethodInvocation *invocation,
                     gpointer user_data)
{
	NML2tpPlugin *self = NM_L2TP_PLUGIN (user_data);
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	const char *user, *password, *domain;
	gchar *username;

	remove_timeout_handler (NM_L2TP_PLUGIN (user_data));

	s_vpn = nm_connection_get_setting_vpn (priv->connection);
	g_assert (s_vpn);

	/* Username; try L2TP specific username first, then generic username */
	user = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_USER);
	if (!user || !strlen (user))
		user = nm_setting_vpn_get_user_name (s_vpn);
	if (!user || !strlen (user)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_VPN_PLUGIN_ERROR,
		                                               NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                                               _("Missing VPN username."));
		return FALSE;
	}

	password = nm_setting_vpn_get_secret (s_vpn, NM_L2TP_KEY_PASSWORD);
	if (!password || !strlen (password)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_VPN_PLUGIN_ERROR,
		                                               NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                                               _("Missing or invalid VPN password."));
		return FALSE;;
	}

	/* Domain is optional */
	domain = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_DOMAIN);

	/* Success */
	if (domain && strlen (domain))
		username = g_strdup_printf ("%s\\%s", domain, user);
	else
		username = g_strdup (user);

	nmdbus_l2tp_ppp_complete_need_secrets (object, invocation, username, password);
	g_free (username);

	return TRUE;
}

static gboolean
handle_set_state (NMDBusL2tpPpp *object,
                  GDBusMethodInvocation *invocation,
                  guint arg_state,
                  gpointer user_data)
{
	remove_timeout_handler (NM_L2TP_PLUGIN (user_data));
	if (arg_state == NM_PPP_STATUS_DEAD || arg_state == NM_PPP_STATUS_DISCONNECT)
		nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (user_data), NULL);

	g_dbus_method_invocation_return_value (invocation, NULL);
	return TRUE;
}

static gboolean
handle_set_ip4_config (NMDBusL2tpPpp *object,
                       GDBusMethodInvocation *invocation,
                       GVariant *arg_config,
                       gpointer user_data)
{
	NML2tpPlugin *plugin = NM_L2TP_PLUGIN (user_data);
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	GVariantIter iter;
	const char *key;
	GVariant *value;
	GVariantBuilder builder;
	GVariant *new_config;

	remove_timeout_handler (plugin);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_iter_init (&iter, arg_config);
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

	nm_vpn_service_plugin_set_ip4_config (NM_VPN_SERVICE_PLUGIN (plugin), new_config);
	g_variant_unref (new_config);

	g_dbus_method_invocation_return_value (invocation, NULL);
	return TRUE;
}


static gboolean
lookup_gateway (NML2tpPlugin *self,
                const char *src,
                GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (self);
	const char *p = src;
	gboolean is_name = FALSE;
	struct in_addr naddr;
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int err;
	char buf[INET_ADDRSTRLEN];

	g_return_val_if_fail (src != NULL, FALSE);

	if (priv->saddr) {
		g_free (priv->saddr);
		priv->saddr = NULL;
	}

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
			return nm_l2tp_ipsec_error(error, "couldn't convert L2TP VPN gateway IP address.");
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
		return nm_l2tp_ipsec_error(error, "couldn't look up L2TP VPN gateway IP address ");
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
		return nm_l2tp_ipsec_error(error, "no usable addresses returned for L2TP VPN gateway ");
	}

	priv->naddr = naddr.s_addr;
	priv->saddr = g_strdup (inet_ntop (AF_INET, &naddr, buf, sizeof (buf)));

	return TRUE;
}


static gboolean
real_connect (NMVpnServicePlugin *plugin,
              NMConnection *connection,
              GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	const char *gwaddr;
	const char *value;

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_ENABLE);
	_LOGI ("ipsec enable flag: %s", value ? value : "(null)");
    priv->is_libreswan = TRUE;
	if(value && !strcmp(value,"yes")) {

		if (!(value=nm_find_ipsec ())) {
			return nm_l2tp_ipsec_error(error, "Could not find the ipsec binary. Is Libreswan or strongSwan installed?");
		}
		strncpy (priv->ipsec_binary_path, value, sizeof(priv->ipsec_binary_path));

		priv->is_libreswan = check_is_libreswan (priv->ipsec_binary_path);
		if (!priv->is_libreswan && !check_is_strongswan (priv->ipsec_binary_path)) {
			return nm_l2tp_ipsec_error (error, "Neither Libreswan nor strongSwan were found.");
		}
	}

	gwaddr = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_GATEWAY);
	if (!gwaddr || !strlen (gwaddr)) {
		return nm_l2tp_ipsec_error(error, "Invalid or missing L2TP gateway.");
	}

	/* Look up the IP address of the L2TP server; if the server has multiple
	 * addresses, because we can't get the actual IP used back from xl2tp itself,
	 * we need to do name->addr conversion here and only pass the IP address
	 * down to pppd/l2tp.  If only xl2tp could somehow return the IP address it's
	 * using for the connection, we wouldn't need to do this...
	 */
	if (!lookup_gateway (NM_L2TP_PLUGIN (plugin), gwaddr, error))
		return FALSE;

	if (!nm_l2tp_properties_validate (s_vpn, error))
		return FALSE;

	if (!nm_l2tp_secrets_validate (s_vpn, error))
		return FALSE;

	if (!nm_l2tp_config_write (NM_L2TP_PLUGIN (plugin), s_vpn, error))
		return FALSE;

	g_clear_object (&priv->connection);
	priv->connection = g_object_ref (connection);

	if (getenv ("NM_L2TP_DUMP_CONNECTION") || _LOGD_enabled ())
		nm_connection_dump (connection);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_L2TP_KEY_IPSEC_ENABLE);
	if(value && !strcmp(value,"yes")) {
		_LOGI ("starting ipsec");
		if (!nm_l2tp_start_ipsec(NM_L2TP_PLUGIN (plugin), s_vpn, error))
			return FALSE;
		priv->ipsec_up = TRUE;
	}

	return nm_l2tp_start_l2tpd_binary (NM_L2TP_PLUGIN (plugin),
	                                  s_vpn,
	                                  error);
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);

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

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **err)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid_l2tpd) {
		if (kill (priv->pid_l2tpd, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid_l2tpd));
		else
			kill (priv->pid_l2tpd, SIGKILL);

		_LOGI ("Terminated xl2tpd daemon with PID %d.", priv->pid_l2tpd);
		priv->pid_l2tpd = 0;
	}

	if(priv->ipsec_up) {
		nm_l2tp_stop_ipsec (priv);
	}

	g_clear_object (&priv->connection);
	if (priv->saddr) {
		g_free (priv->saddr);
		priv->saddr = NULL;
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
		g_clear_object (&priv->connection);
		if (priv->saddr) {
			g_free (priv->saddr);
			priv->saddr = NULL;
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
	GDBusInterfaceSkeleton *skeleton = NULL;

	if (priv->dbus_skeleton)
		skeleton = G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton);

	if (skeleton) {
		if (g_dbus_interface_skeleton_get_object_path (skeleton))
			g_dbus_interface_skeleton_unexport (skeleton);
		g_signal_handlers_disconnect_by_func (skeleton, handle_need_secrets, object);
		g_signal_handlers_disconnect_by_func (skeleton, handle_set_state, object);
		g_signal_handlers_disconnect_by_func (skeleton, handle_set_ip4_config, object);
	}

	g_clear_object (&priv->connection);
	if (priv->saddr) {
		g_free (priv->saddr);
		priv->saddr = NULL;
	}

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

static GInitableIface *ginitable_parent_iface = NULL;

static gboolean
init_sync (GInitable *object, GCancellable *cancellable, GError **error)
{
	NML2tpPluginPrivate *priv = NM_L2TP_PLUGIN_GET_PRIVATE (object);
	GDBusConnection *bus;

	if (!ginitable_parent_iface->init (object, cancellable, error))
		return FALSE;

	g_signal_connect (G_OBJECT (object), "state-changed", G_CALLBACK (state_changed_cb), NULL);

	bus = nm_vpn_service_plugin_get_connection (NM_VPN_SERVICE_PLUGIN (object)),
	priv->dbus_skeleton = nmdbus_l2tp_ppp_skeleton_new ();
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton),
	                                       bus,
	                                       NM_DBUS_PATH_L2TP_PPP,
	                                       error)) {
		g_prefix_error (error, "Failed to export helper interface: ");
		g_object_unref (bus);
		return FALSE;
	}

	g_dbus_connection_register_object (bus, NM_DBUS_PATH_L2TP_PPP,
	                                   nmdbus_l2tp_ppp_interface_info (),
	                                   NULL, NULL, NULL, NULL);

	g_signal_connect (priv->dbus_skeleton, "handle-need-secrets", G_CALLBACK (handle_need_secrets), object);
	g_signal_connect (priv->dbus_skeleton, "handle-set-state", G_CALLBACK (handle_set_state), object);
	g_signal_connect (priv->dbus_skeleton, "handle-set-ip4-config", G_CALLBACK (handle_set_ip4_config), object);

	g_object_unref (bus);
	return TRUE;
}

static void
nm_l2tp_plugin_initable_iface_init (GInitableIface *iface)
{
	ginitable_parent_iface = g_type_interface_peek_parent (iface);
	iface->init = init_sync;
}

NML2tpPlugin *
nm_l2tp_plugin_new (const char *bus_name)
{
	NML2tpPlugin *plugin;
	GError *error = NULL;

	plugin = g_initable_new (NM_TYPE_L2TP_PLUGIN, NULL, &error,
	                         NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name,
	                         NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER, !_LOGD_enabled (),
	                         NULL);
	if (!plugin) {
		_LOGW ("Failed to initialize a plugin instance: %s", error->message);
		g_error_free (error);
	}

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
	GError *error = NULL;
	gs_free char *bus_name_free = NULL;
	const char *bus_name;
	char sbuf[30];

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &gl.debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{ "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name_free, N_("D-Bus name to use for this instance"), NULL },
		{NULL}
	};

	nm_g_type_init ();

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

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
		g_printerr ("Error parsing the command line options: %s\n", error->message);
		g_option_context_free (opt_ctx);
		g_error_free (error);
		return EXIT_FAILURE;
	}
	g_option_context_free (opt_ctx);

	bus_name = bus_name_free ?: NM_DBUS_SERVICE_L2TP;

	if (getenv ("NM_PPP_DEBUG"))
		gl.debug = TRUE;

	gl.log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
	                                             10, 0, LOG_DEBUG,
	                                             gl.debug ? LOG_INFO : LOG_NOTICE);

	_LOGD ("nm-l2tp-service (version " DIST_VERSION ") starting...");
	_LOGD (" uses%s --bus-name \"%s\"", bus_name_free ? "" : " default", bus_name);

	setenv ("NM_VPN_LOG_LEVEL", nm_sprintf_buf (sbuf, "%d", gl.log_level), TRUE);
	setenv ("NM_VPN_LOG_PREFIX_TOKEN", nm_sprintf_buf (sbuf, "%ld", (long) getpid ()), TRUE);
	setenv ("NM_DBUS_SERVICE_L2TP", bus_name, 0);

	plugin = nm_l2tp_plugin_new (bus_name);
	if (!plugin)
		exit (EXIT_FAILURE);

	main_loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), main_loop);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	return EXIT_SUCCESS;
}
