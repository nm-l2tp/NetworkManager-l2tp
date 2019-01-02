/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager-l2tp - Authentication Dialog
 *
 * Dan Williams <dcbw@redhat.com>
 * Tim Niemueller <tim@niemueller.de>
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
 * (C) Copyright 2004 - 2018 Red Hat, Inc.
 *               2005 Tim Niemueller [www.niemueller.de]
 */

#include "nm-default.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <gtk/gtk.h>
#include <libsecret/secret.h>

#include <nma-vpn-password-dialog.h>

#include "nm-l2tp-crypto-openssl.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

static const SecretSchema network_manager_secret_schema = {
	"org.freedesktop.NetworkManager.Connection",
	SECRET_SCHEMA_DONT_MATCH_NAME,
	{
		{ KEYRING_UUID_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SN_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SK_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ NULL, 0 },
	}
};

#define UI_KEYFILE_GROUP "VPN Plugin UI"

static char *
keyring_lookup_secret (const char *uuid, const char *secret_name)
{
	GHashTable *attrs;
	GList *list;
	char *secret = NULL;

	attrs = secret_attributes_build (&network_manager_secret_schema,
	                                 KEYRING_UUID_TAG, uuid,
	                                 KEYRING_SN_TAG, NM_SETTING_VPN_SETTING_NAME,
	                                 KEYRING_SK_TAG, secret_name,
	                                 NULL);

	list = secret_service_search_sync (NULL, &network_manager_secret_schema, attrs,
	                                   SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS,
	                                   NULL, NULL);
	if (list && list->data) {
		SecretItem *item = list->data;
		SecretValue *value = secret_item_get_secret (item);

		if (value) {
			secret = g_strdup (secret_value_get (value, NULL));
			secret_value_unref (value);
		}
	}

	g_list_free_full (list, g_object_unref);
	g_hash_table_unref (attrs);
	return secret;
}

/*****************************************************************/

typedef void (*NoSecretsRequiredFunc) (void);

/* Returns TRUE on success, FALSE on cancel */
typedef gboolean (*AskUserFunc) (const char *vpn_name,
                                 const char *prompt,
                                 gboolean need_password,
                                 const char *existing_password,
                                 char **out_new_password,
                                 gboolean need_user_certpass,
                                 const char *existing_user_certpass,
                                 char **out_new_user_certpass,
                                 gboolean need_machine_certpass,
                                 const char *existing_machine_certpass,
                                 char **out_new_machine_certpass);

typedef void (*FinishFunc) (const char *vpn_name,
                            const char *prompt,
                            gboolean allow_interaction,
                            gboolean need_password,
                            const char *password,
                            gboolean need_user_certpass,
                            const char *user_certpass,
                            gboolean need_machine_certpass,
                            const char *machine_certpass);

/*****************************************************************/
/* External UI mode stuff */

static void
keyfile_add_entry_info (GKeyFile    *keyfile,
                        const gchar *key,
                        const gchar *value,
                        const gchar *label,
                        gboolean     is_secret,
                        gboolean     should_ask)
{
	g_key_file_set_string (keyfile, key, "Value", value);
	g_key_file_set_string (keyfile, key, "Label", label);
	g_key_file_set_boolean (keyfile, key, "IsSecret", is_secret);
	g_key_file_set_boolean (keyfile, key, "ShouldAsk", should_ask);
}

static void
keyfile_print_stdout (GKeyFile *keyfile)
{
	gchar *data;
	gsize length;

	data = g_key_file_to_data (keyfile, &length, NULL);

	fputs (data, stdout);

	g_free (data);
}

static void
eui_no_secrets_required (void)
{
	GKeyFile *keyfile;

	keyfile = g_key_file_new ();

	g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
	keyfile_add_entry_info (keyfile, NM_L2TP_KEY_NOSECRET, "true", "", TRUE, FALSE);
	keyfile_print_stdout (keyfile);
	g_key_file_unref (keyfile);
}

static void
eui_finish (const char *vpn_name,
            const char *prompt,
            gboolean allow_interaction,
            gboolean need_password,
            const char *existing_password,
            gboolean need_user_certpass,
            const char *existing_user_certpass,
            gboolean need_machine_certpass,
            const char *existing_machine_certpass)
{
	GKeyFile *keyfile;
	char *title;

	keyfile = g_key_file_new ();

	g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
	g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Description", prompt);

	title = g_strdup_printf (_("Authenticate VPN %s"), vpn_name);
	g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Title", title);
	g_free (title);

	keyfile_add_entry_info (keyfile,
	                        NM_L2TP_KEY_PASSWORD,
	                        existing_password ? existing_password : "",
	                        _("Password:"),
	                        TRUE,
	                        need_password && allow_interaction);

	keyfile_add_entry_info (keyfile,
	                        NM_L2TP_KEY_USER_CERTPASS,
	                        existing_user_certpass ? existing_user_certpass : "",
	                        _("User Certificate password:"),
	                        TRUE,
	                        need_user_certpass && allow_interaction);

	keyfile_add_entry_info (keyfile,
	                        NM_L2TP_KEY_MACHINE_CERTPASS,
	                        existing_machine_certpass ? existing_machine_certpass : "",
	                        _("Machine Certificate password:"),
	                        TRUE,
	                        need_machine_certpass && allow_interaction);

	keyfile_print_stdout (keyfile);
	g_key_file_unref (keyfile);
}

/*****************************************************************/

static void
std_no_secrets_required (void)
{
	printf ("%s\n%s\n\n\n", NM_L2TP_KEY_NOSECRET, "true");
}

static gboolean
std_ask_user (const char *vpn_name,
              const char *prompt,
              gboolean need_password,
              const char *existing_password,
              char **out_new_password,
              gboolean need_user_certpass,
              const char *existing_user_certpass,
              char **out_new_user_certpass,
              gboolean need_machine_certpass,
              const char *existing_machine_certpass,
              char **out_new_machine_certpass)
{
	NMAVpnPasswordDialog *dialog;
	gboolean success = FALSE;

	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (prompt != NULL, FALSE);
	g_return_val_if_fail (out_new_password != NULL, FALSE);
	g_return_val_if_fail (out_new_user_certpass != NULL, FALSE);
	g_return_val_if_fail (out_new_machine_certpass != NULL, FALSE);

	gtk_init (NULL, NULL);

	dialog = NMA_VPN_PASSWORD_DIALOG (nma_vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL));

	/* pre-fill dialog with existing passwords */
	nma_vpn_password_dialog_set_show_password (dialog, need_password);
	if (need_password)
		nma_vpn_password_dialog_set_password (dialog, existing_password);

	nma_vpn_password_dialog_set_show_password_secondary (dialog, need_user_certpass);
	if (need_user_certpass) {
		nma_vpn_password_dialog_set_password_secondary_label (dialog, _("_User Certificate password:") );
		nma_vpn_password_dialog_set_password_secondary (dialog, existing_user_certpass);
	}

	nma_vpn_password_dialog_set_show_password_ternary (dialog, need_machine_certpass);
	if (need_machine_certpass) {
		nma_vpn_password_dialog_set_password_ternary_label (dialog, _("_Machine Certificate password:"));
		nma_vpn_password_dialog_set_password_ternary (dialog, existing_machine_certpass);
	}

	gtk_widget_show (GTK_WIDGET (dialog));
	if (nma_vpn_password_dialog_run_and_block (dialog)) {
		if (need_password)
			*out_new_password = g_strdup (nma_vpn_password_dialog_get_password (dialog));
		if (need_user_certpass)
			*out_new_user_certpass = g_strdup (nma_vpn_password_dialog_get_password_secondary (dialog));
		if (need_machine_certpass)
			*out_new_machine_certpass = g_strdup (nma_vpn_password_dialog_get_password_ternary (dialog));

		success = TRUE;
	}

	gtk_widget_destroy (GTK_WIDGET (dialog));
	return success;
}

static void
wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

static void
std_finish (const char *vpn_name,
            const char *prompt,
            gboolean allow_interaction,
            gboolean need_password,
            const char *password,
            gboolean need_user_certpass,
            const char *user_certpass,
            gboolean need_machine_certpass,
            const char *machine_certpass)
{
	/* Send the passwords back to our parent */
	if (password)
		printf ("%s\n%s\n", NM_L2TP_KEY_PASSWORD, password);
	if (user_certpass)
		printf ("%s\n%s\n", NM_L2TP_KEY_USER_CERTPASS, user_certpass);
	if (machine_certpass)
		printf ("%s\n%s\n", NM_L2TP_KEY_MACHINE_CERTPASS, machine_certpass);
	printf ("\n\n");

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* Wait for quit signal */
	wait_for_quit ();
}

/*****************************************************************/

static void
get_existing_passwords (GHashTable *vpn_data,
                        GHashTable *existing_secrets,
                        const char *vpn_uuid,
                        gboolean need_password,
                        gboolean need_user_certpass,
                        gboolean need_machine_certpass,
                        char **out_password,
                        char **out_user_certpass,
                        char **out_machine_certpass)
{
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMSettingSecretFlags user_cp_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMSettingSecretFlags machine_cp_flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_if_fail (out_password != NULL);
	g_return_if_fail (out_user_certpass != NULL);
	g_return_if_fail (out_machine_certpass != NULL);

	nm_vpn_service_plugin_get_secret_flags (vpn_data, NM_L2TP_KEY_PASSWORD, &pw_flags);
	if (need_password) {
		if (!(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_password = g_strdup (g_hash_table_lookup (existing_secrets, NM_L2TP_KEY_PASSWORD));
			if (!*out_password)
				*out_password = keyring_lookup_secret (vpn_uuid, NM_L2TP_KEY_PASSWORD);
		}
	}

	nm_vpn_service_plugin_get_secret_flags (vpn_data, NM_L2TP_KEY_USER_CERTPASS, &user_cp_flags);
	if (need_user_certpass) {
		if (!(user_cp_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_user_certpass = g_strdup (g_hash_table_lookup (existing_secrets, NM_L2TP_KEY_USER_CERTPASS));
			if (!*out_user_certpass)
				*out_user_certpass = keyring_lookup_secret (vpn_uuid, NM_L2TP_KEY_USER_CERTPASS);
		}
	}

	nm_vpn_service_plugin_get_secret_flags (vpn_data, NM_L2TP_KEY_MACHINE_CERTPASS, &machine_cp_flags);
	if (need_machine_certpass) {
		if (!(machine_cp_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_machine_certpass = g_strdup (g_hash_table_lookup (existing_secrets, NM_L2TP_KEY_MACHINE_CERTPASS));
			if (!*out_machine_certpass)
				*out_machine_certpass = keyring_lookup_secret (vpn_uuid, NM_L2TP_KEY_MACHINE_CERTPASS);
		}
	}
}

static char *
get_passwords_required (GHashTable *data,
                        gboolean *out_need_password,
                        gboolean *out_need_user_certpass,
                        gboolean *out_need_machine_certpass)
{
	const char *ctype, *val;
	NMSettingSecretFlags flags;

	*out_need_password = FALSE;
	*out_need_user_certpass = FALSE;
	*out_need_machine_certpass = FALSE;

	ctype = g_hash_table_lookup (data, NM_L2TP_KEY_AUTH_TYPE);
	g_return_val_if_fail (ctype != NULL, NULL);

	if (nm_streq0 (ctype, NM_L2TP_AUTHTYPE_TLS)) {
		/* Encrypted PKCS#12 certificate or private key password */
		val = g_hash_table_lookup (data, NM_L2TP_KEY_USER_KEY);
		if (val)
			crypto_file_format (val, out_need_user_certpass, NULL);

	} else if (nm_streq0 (ctype, NM_L2TP_AUTHTYPE_PASSWORD)) {
		flags = NM_SETTING_SECRET_FLAG_NONE;
		nm_vpn_service_plugin_get_secret_flags (data, NM_L2TP_KEY_PASSWORD, &flags);
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			*out_need_password = TRUE;
	}

	ctype = g_hash_table_lookup (data, NM_L2TP_KEY_IPSEC_AUTH_TYPE);
	g_return_val_if_fail (ctype != NULL, NULL);

	if (nm_streq0 (ctype, NM_L2TP_AUTHTYPE_TLS)) {
		/* Encrypted PKCS#12 certificate or private key password */
		val = g_hash_table_lookup (data, NM_L2TP_KEY_MACHINE_KEY);
		if (val)
			crypto_file_format (val, out_need_machine_certpass, NULL);
	}

	return NULL;
}

int
main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE;
	gchar *vpn_name = NULL;
	gchar *vpn_uuid = NULL;
	gchar *vpn_service = NULL;
	gs_unref_hashtable GHashTable *data = NULL;
	gs_unref_hashtable GHashTable *secrets = NULL;
	gboolean need_password = FALSE;
	gboolean need_user_certpass = FALSE;
	gboolean need_machine_certpass = FALSE;
	gs_free char *prompt = NULL;
	nm_auto_free_secret char *new_password = NULL;
	nm_auto_free_secret char *new_user_certpass = NULL;
	nm_auto_free_secret char *new_machine_certpass = NULL;
	nm_auto_free_secret char *existing_password = NULL;
	nm_auto_free_secret char *existing_user_certpass = NULL;
	nm_auto_free_secret char *existing_machine_certpass = NULL;
	gboolean external_ui_mode = FALSE;
	gboolean ask_user;
	NoSecretsRequiredFunc no_secrets_required_func;
	AskUserFunc ask_user_func;
	FinishFunc finish_func;

	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
			{ "external-ui-mode", 0, 0, G_OPTION_ARG_NONE, &external_ui_mode, "External UI mode", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	context = g_option_context_new ("- l2tp auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_add_group (context, gtk_get_option_group (FALSE));
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (vpn_uuid == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "A connection UUID, name, and VPN plugin service name are required.\n");
		return EXIT_FAILURE;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_L2TP) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_L2TP);
		return EXIT_FAILURE;
	}

	if (!nm_vpn_service_plugin_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return EXIT_FAILURE;
	}

	if (external_ui_mode) {
		no_secrets_required_func = eui_no_secrets_required;
		ask_user_func = NULL;
		finish_func = eui_finish;
	} else {
		no_secrets_required_func = std_no_secrets_required;
		ask_user_func = std_ask_user;
		finish_func = std_finish;
	}

	/* Determine which passwords are actually required,
	 * from looking at the VPN configuration.
	 */
	prompt = get_passwords_required (data, &need_password, &need_user_certpass, &need_machine_certpass);
	if (!prompt)
		prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network “%s”."), vpn_name);

	/* Exit early if we don't need any passwords */
	if (!need_password && !need_user_certpass && !need_machine_certpass) {
		no_secrets_required_func ();
		return EXIT_SUCCESS;
	}

	get_existing_passwords (data,
	                        secrets,
	                        vpn_uuid,
	                        need_password,
	                        need_user_certpass,
	                        need_machine_certpass,
	                        &existing_password,
	                        &existing_user_certpass,
	                        &existing_machine_certpass);
	if (need_password && !existing_password)
		ask_user = TRUE;
	else if (need_user_certpass && !existing_user_certpass)
		ask_user = TRUE;
	else if (need_machine_certpass && !existing_machine_certpass)
		ask_user = TRUE;
	else
		ask_user = FALSE;

	/* If interaction is allowed then ask the user, otherwise pass back
	 * whatever existing secrets we can find.
	 */
	if (   ask_user_func
	    && allow_interaction
	    && (ask_user || retry)) {
		if (!ask_user_func (vpn_name,
		                    prompt,
		                    need_password,
		                    existing_password,
		                    &new_password,
		                    need_user_certpass,
		                    existing_user_certpass,
		                    &new_user_certpass,
		                    need_machine_certpass,
		                    existing_machine_certpass,
		                    &new_machine_certpass))
			return EXIT_FAILURE;
	}

	finish_func (vpn_name,
	             prompt,
	             allow_interaction,
	             need_password,
	             new_password ? new_password : existing_password,
	             need_user_certpass,
	             new_user_certpass ? new_user_certpass : existing_user_certpass,
	             need_machine_certpass,
	             new_machine_certpass ? new_machine_certpass : existing_machine_certpass);
	return EXIT_SUCCESS;
}
