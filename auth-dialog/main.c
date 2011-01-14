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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <nm-setting-vpn.h>

#include "src/nm-l2tp-service.h"
#include "common-gnome/keyring-helpers.h"
#include "gnome-two-password-dialog.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

static gboolean
get_secrets (const char *vpn_uuid,
             const char *vpn_name,
             const char *vpn_service,
             gboolean retry,
             char **password)
{
	GnomeTwoPasswordDialog *dialog;
	gboolean is_session = TRUE;
	char *prompt;

	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (*password == NULL, FALSE);

	*password = keyring_helpers_lookup_secret (vpn_uuid, NM_L2TP_KEY_PASSWORD, &is_session);
	if (!retry && *password)
		return TRUE;

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);
	dialog = GNOME_TWO_PASSWORD_DIALOG (gnome_two_password_dialog_new (_("Authenticate VPN"), prompt, NULL, NULL, FALSE));
	g_free (prompt);

	gnome_two_password_dialog_set_show_username (dialog, FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (dialog, FALSE);
	gnome_two_password_dialog_set_show_domain (dialog, FALSE);
	gnome_two_password_dialog_set_show_remember (dialog, TRUE);
	gnome_two_password_dialog_set_show_password_secondary (dialog, FALSE);

	/* If nothing was found in the keyring, default to not remembering any secrets */
	if (*password) {
		/* Otherwise set default remember based on which keyring the secrets were found in */
		if (is_session)
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION);
		else
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER);
	} else
		gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING);

	/* if retrying, pre-fill dialog with the password */
	if (*password) {
		gnome_two_password_dialog_set_password (dialog, *password);
		g_free (*password);
		*password = NULL;
	}

	gtk_widget_show (GTK_WIDGET (dialog));

	if (gnome_two_password_dialog_run_and_block (dialog)) {
		const char *keyring = NULL;
		gboolean save = FALSE;

		*password = gnome_two_password_dialog_get_password (dialog);

		switch (gnome_two_password_dialog_get_remember (dialog)) {
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION:
			keyring = "session";
			/* Fall through */
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
			save = TRUE;
			break;
		default:
			break;
		}

		if (save) {
			if (*password) {
				keyring_helpers_save_secret (vpn_uuid, vpn_name, keyring,
					   	NM_L2TP_KEY_PASSWORD, *password);
			}
		}
	}

	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));

	return TRUE;
}

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE;
	gchar *vpn_name = NULL;
	gchar *vpn_uuid = NULL;
	gchar *vpn_service = NULL;
	char *password = NULL;
	char buf[1];
	int ret;
	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
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


	if (vpn_uuid == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "Have to supply UUID, name, and service\n");
		return EXIT_FAILURE;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_L2TP) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_L2TP);
		return EXIT_FAILURE;
	}

	if (!get_secrets (vpn_uuid, vpn_name, vpn_service, retry, &password))
		return EXIT_FAILURE;

	/* dump the passwords to stdout */
	printf ("%s\n%s\n", NM_L2TP_KEY_PASSWORD, password);
	printf ("\n\n");

	if (password) {
		memset (password, 0, strlen (password));
		gnome_keyring_memory_free (password);
	}

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* wait for data on stdin  */
	ret = fread (buf, sizeof (char), sizeof (buf), stdin);

	return EXIT_SUCCESS;
}
