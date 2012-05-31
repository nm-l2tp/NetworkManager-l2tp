/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * (C) Copyright 2008 - 2011 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>

#include <nm-setting-vpn.h>
#include <nm-vpn-plugin-utils.h>

#include "src/nm-l2tp-service.h"
#include "vpn-password-dialog.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

#define UI_KEYFILE_GROUP "VPN Plugin UI"

static char *
keyring_lookup_secret (const char *uuid, const char *secret_name)
{
	GList *found_list = NULL;
	GnomeKeyringResult ret;
	GnomeKeyringFound *found;
	char *secret = NULL;

	ret = gnome_keyring_find_itemsv_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      &found_list,
	                                      KEYRING_UUID_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      uuid,
	                                      KEYRING_SN_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      NM_SETTING_VPN_SETTING_NAME,
	                                      KEYRING_SK_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      secret_name,
	                                      NULL);
	if (ret == GNOME_KEYRING_RESULT_OK && found_list) {
		found = g_list_nth_data (found_list, 0);
		secret = gnome_keyring_memory_strdup (found->secret);
	}

	gnome_keyring_found_list_free (found_list);
	return secret;
}

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

#if !GLIB_CHECK_VERSION(2,32,0)
#define g_key_file_unref g_key_file_free
#endif

static gboolean
get_secrets (const char *vpn_uuid,
             const char *vpn_name,
             gboolean retry,
             gboolean allow_interaction,
             gboolean external_ui_mode,
             const char *in_pw,
             char **out_pw,
             NMSettingSecretFlags pw_flags)
{
	VpnPasswordDialog *dialog;
	char *prompt, *pw = NULL;
	const char *new_password = NULL;

	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (out_pw != NULL, FALSE);
	g_return_val_if_fail (*out_pw == NULL, FALSE);

	/* Get the existing secret, if any */
	if (   !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
	    && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		if (in_pw)
			pw = gnome_keyring_memory_strdup (in_pw);
		else
			pw = keyring_lookup_secret (vpn_uuid, NM_L2TP_KEY_PASSWORD);
	}

	/* Don't ask if the passwords is unused */
	if (pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
		gnome_keyring_memory_free (pw);
		return TRUE;
	}

	/* Otherwise, we have no saved password, or the password flags indicated
	 * that the password should never be saved.
	 */
	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);

	if (external_ui_mode) {
		GKeyFile *keyfile;

		keyfile = g_key_file_new ();

		g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
		g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Description", prompt);
		g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Title", _("Authenticate VPN"));

		keyfile_add_entry_info (keyfile, NM_L2TP_KEY_PASSWORD, pw ? pw : "", _("Password:"), TRUE, allow_interaction);

		keyfile_print_stdout (keyfile);
		g_key_file_unref (keyfile);
		goto out;
	} else if (   allow_interaction == FALSE
	           || (!retry && pw && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))) {
		/* If interaction isn't allowed, just return existing secrets.
		 * Also, don't ask the user if we don't need a new password (ie, !retry),
		 * we have an existing PW, and the password is saved.
		 */

		*out_pw = pw;
		g_free (prompt);
		return TRUE;
	}


	dialog = (VpnPasswordDialog *) vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL);

	vpn_password_dialog_set_show_password_secondary (dialog, FALSE);

	/* pre-fill dialog with the password */
	if (pw && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
		vpn_password_dialog_set_password (dialog, pw);

	gtk_widget_show (GTK_WIDGET (dialog));

	if (vpn_password_dialog_run_and_block (dialog)) {

		new_password = vpn_password_dialog_get_password (dialog);
		if (new_password)
			*out_pw = gnome_keyring_memory_strdup (new_password);
	}

	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));

 out:
	g_free (prompt);

	return TRUE;
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

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE, external_ui_mode = FALSE;
	char *vpn_name = NULL, *vpn_uuid = NULL, *vpn_service = NULL, *password = NULL;
	GHashTable *data = NULL, *secrets = NULL;
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
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

	gtk_init (&argc, &argv);

	context = g_option_context_new ("- l2tp auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (!vpn_uuid || !vpn_service || !vpn_name) {
		fprintf (stderr, "A connection UUID, name, and VPN plugin service name are required.\n");
		return 1;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_L2TP) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_L2TP);
		return 1;
	}

	if (!nm_vpn_plugin_utils_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return 1;
	}

	nm_vpn_plugin_utils_get_secret_flags (secrets, NM_L2TP_KEY_PASSWORD, &pw_flags);

	if (!get_secrets (vpn_uuid, vpn_name, retry, allow_interaction, external_ui_mode,
	                  g_hash_table_lookup (secrets, NM_L2TP_KEY_PASSWORD),
	                  &password,
	                  pw_flags))
		return 1;

	if (!external_ui_mode) {
		/* dump the passwords to stdout */
		if (password)
			printf ("%s\n%s\n", NM_L2TP_KEY_PASSWORD, password);
		printf ("\n\n");

		gnome_keyring_memory_free (password);

		/* for good measure, flush stdout since Kansas is going Bye-Bye */
		fflush (stdout);

		/* Wait for quit signal */
		wait_for_quit ();
	}

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	return 0;
}
