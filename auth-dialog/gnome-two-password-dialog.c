/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */

/* gnome-password-dialog.c - A use password prompting dialog widget.

   Copyright (C) 1999, 2000 Eazel, Inc.

   The Gnome Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the ree Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

   Authors: Ramiro Estrugo <ramiro@eazel.com>
*/

#include <config.h>
#include "gnome-two-password-dialog.h"

#include <glib/gi18n.h>
#include <gtk/gtk.h>


struct GnomeTwoPasswordDialogDetails
{
	/* Attributes */
	gboolean readonly_username;
	gboolean readonly_domain;

	gboolean show_username;
	gboolean show_domain;
	gboolean show_password;
	gboolean show_password_secondary;
	
	/* TODO: */
	gboolean remember;
	char *remember_label_text;

	/* Internal widgetry and flags */
	GtkWidget *username_entry;
	GtkWidget *password_entry;
	GtkWidget *password_entry_secondary;
	GtkWidget *domain_entry;

	GtkWidget *table_alignment;
	GtkWidget *table;
	
	GtkWidget *remember_session_button;
	GtkWidget *remember_forever_button;

	GtkWidget *radio_vbox;
	GtkWidget *connect_with_no_userpass_button;
	GtkWidget *connect_with_userpass_button;

	gboolean anon_support_on;

	char *secondary_password_label;
};

/* Caption table rows indices */
static const guint CAPTION_TABLE_USERNAME_ROW = 0;
static const guint CAPTION_TABLE_PASSWORD_ROW = 1;

/* GnomeTwoPasswordDialogClass methods */
static void gnome_two_password_dialog_class_init (GnomeTwoPasswordDialogClass *password_dialog_class);
static void gnome_two_password_dialog_init       (GnomeTwoPasswordDialog      *password_dialog);

/* GObjectClass methods */
static void gnome_two_password_dialog_finalize         (GObject                *object);


/* GtkDialog callbacks */
static void dialog_show_callback                 (GtkWidget              *widget,
						  gpointer                callback_data);
static void dialog_close_callback                (GtkWidget              *widget,
						  gpointer                callback_data);

static gpointer parent_class;

GType
gnome_two_password_dialog_get_type (void)
{
	static GType type = 0;

	if (!type) {
		static const GTypeInfo info = {
			sizeof (GnomeTwoPasswordDialogClass),
                        NULL, NULL,
			(GClassInitFunc) gnome_two_password_dialog_class_init,
                        NULL, NULL,
			sizeof (GnomeTwoPasswordDialog), 0,
			(GInstanceInitFunc) gnome_two_password_dialog_init,
			NULL
		};

                type = g_type_register_static (gtk_dialog_get_type(), 
					       "GnomeTwoPasswordDialog", 
					       &info, 0);

		parent_class = g_type_class_ref (gtk_dialog_get_type());
	}

	return type;
}


static void
gnome_two_password_dialog_class_init (GnomeTwoPasswordDialogClass * klass)
{
	G_OBJECT_CLASS (klass)->finalize = gnome_two_password_dialog_finalize;
}

static void
gnome_two_password_dialog_init (GnomeTwoPasswordDialog *password_dialog)
{
	password_dialog->details = g_new0 (GnomeTwoPasswordDialogDetails, 1);
	password_dialog->details->show_username = TRUE;
	password_dialog->details->show_password = TRUE;
	password_dialog->details->show_password_secondary = TRUE;
	password_dialog->details->anon_support_on = FALSE;

	password_dialog->details->secondary_password_label = g_strdup ( _("_Secondary Password:") );
}

/* GObjectClass methods */
static void
gnome_two_password_dialog_finalize (GObject *object)
{
	GnomeTwoPasswordDialog *password_dialog;
	
	password_dialog = GNOME_TWO_PASSWORD_DIALOG (object);

	g_object_unref (password_dialog->details->username_entry);
	g_object_unref (password_dialog->details->domain_entry);
	g_object_unref (password_dialog->details->password_entry);
	g_object_unref (password_dialog->details->password_entry_secondary);

	g_free (password_dialog->details->remember_label_text);
	g_free (password_dialog->details->secondary_password_label);
	g_free (password_dialog->details);

	if (G_OBJECT_CLASS (parent_class)->finalize != NULL)
		(* G_OBJECT_CLASS (parent_class)->finalize) (object);
}

/* GtkDialog callbacks */
static void
dialog_show_callback (GtkWidget *widget, gpointer callback_data)
{
	GnomeTwoPasswordDialog *password_dialog;

	password_dialog = GNOME_TWO_PASSWORD_DIALOG (callback_data);

	if (GTK_WIDGET_VISIBLE (password_dialog->details->username_entry) &&
	    !password_dialog->details->readonly_username) {
		gtk_widget_grab_focus (password_dialog->details->username_entry);
	} else if (GTK_WIDGET_VISIBLE (password_dialog->details->domain_entry) &&
		   !password_dialog->details->readonly_domain) {
		gtk_widget_grab_focus (password_dialog->details->domain_entry);
	} else if (GTK_WIDGET_VISIBLE (password_dialog->details->password_entry)) {
		gtk_widget_grab_focus (password_dialog->details->password_entry);
	} else if (GTK_WIDGET_VISIBLE (password_dialog->details->password_entry_secondary)) {
		gtk_widget_grab_focus (password_dialog->details->password_entry_secondary);
	}
}

static void
dialog_close_callback (GtkWidget *widget, gpointer callback_data)
{
	gtk_widget_hide (widget);
}

static void
userpass_radio_button_clicked (GtkWidget *widget, gpointer callback_data)
{
	GnomeTwoPasswordDialog *password_dialog;

	password_dialog = GNOME_TWO_PASSWORD_DIALOG (callback_data);

	if (widget == password_dialog->details->connect_with_no_userpass_button) {
		gtk_widget_set_sensitive (
			password_dialog->details->table, FALSE);
	}
	else { /* the other button */
		gtk_widget_set_sensitive (
                        password_dialog->details->table, TRUE);
	}	
}

static void
add_row (GtkWidget *table, int row, const char *label_text, GtkWidget *entry)
{
	GtkWidget *label;

	label = gtk_label_new_with_mnemonic (label_text);
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);

	gtk_table_attach_defaults (GTK_TABLE (table), label,
				   0, 1, row, row + 1);
	gtk_table_attach_defaults (GTK_TABLE (table), entry,
				   1, 2, row, row + 1);

	gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);
}

static void
remove_child (GtkWidget *child, GtkWidget *table)
{
	gtk_container_remove (GTK_CONTAINER (table), child);
}

static void
add_table_rows (GnomeTwoPasswordDialog *password_dialog)
{
	int row;
	GtkWidget *table;
	int offset;

	if (password_dialog->details->anon_support_on) {
		offset = 12;
	}
	else {
		offset = 0;
	}

	gtk_alignment_set_padding (GTK_ALIGNMENT (password_dialog->details->table_alignment),
				   0, 0, offset, 0);

	table = password_dialog->details->table;
	/* This will not kill the entries, since they are ref:ed */
	gtk_container_foreach (GTK_CONTAINER (table),
			       (GtkCallback)remove_child, table);
	
	row = 0;
	if (password_dialog->details->show_username)
		add_row (table, row++, _("_Username:"), password_dialog->details->username_entry);
	if (password_dialog->details->show_domain)
		add_row (table, row++, _("_Domain:"), password_dialog->details->domain_entry);
	if (password_dialog->details->show_password)
		add_row (table, row++, _("_Password:"), password_dialog->details->password_entry);
	if (password_dialog->details->show_password_secondary)
		add_row (table, row++, password_dialog->details->secondary_password_label, 
			 password_dialog->details->password_entry_secondary);

	gtk_widget_show_all (table);
}

static void
username_entry_activate (GtkWidget *widget, GtkWidget *dialog)
{
	GnomeTwoPasswordDialog *password_dialog;

	password_dialog = GNOME_TWO_PASSWORD_DIALOG (dialog);
	
	if (GTK_WIDGET_VISIBLE (password_dialog->details->domain_entry) &&
	    GTK_WIDGET_SENSITIVE (password_dialog->details->domain_entry))
		gtk_widget_grab_focus (password_dialog->details->domain_entry);
	else if (GTK_WIDGET_VISIBLE (password_dialog->details->password_entry) &&
		 GTK_WIDGET_SENSITIVE (password_dialog->details->password_entry))
		gtk_widget_grab_focus (password_dialog->details->password_entry);
	else if (GTK_WIDGET_VISIBLE (password_dialog->details->password_entry_secondary) &&
		 GTK_WIDGET_SENSITIVE (password_dialog->details->password_entry_secondary))
		gtk_widget_grab_focus (password_dialog->details->password_entry_secondary);
}

static void
domain_entry_activate (GtkWidget *widget, GtkWidget *dialog)
{
	GnomeTwoPasswordDialog *password_dialog;

	password_dialog = GNOME_TWO_PASSWORD_DIALOG (dialog);
	
	if (GTK_WIDGET_VISIBLE (password_dialog->details->password_entry) &&
	    GTK_WIDGET_SENSITIVE (password_dialog->details->password_entry))
		gtk_widget_grab_focus (password_dialog->details->password_entry);
	else if (GTK_WIDGET_VISIBLE (password_dialog->details->password_entry_secondary) &&
		 GTK_WIDGET_SENSITIVE (password_dialog->details->password_entry_secondary))
		gtk_widget_grab_focus (password_dialog->details->password_entry_secondary);
}


/* Public GnomeTwoPasswordDialog methods */
GtkWidget *
gnome_two_password_dialog_new (const char	*dialog_title,
			   const char	*message,
			   const char	*username,
			   const char	*password,
			   gboolean	 readonly_username)
{
	GnomeTwoPasswordDialog *password_dialog;
	GtkDialog *dialog;
	GtkWidget *table;
	GtkLabel *message_label;
	GtkWidget *hbox;
	GtkWidget *vbox;
	GtkWidget *main_vbox;
	GtkWidget *dialog_icon;
	GSList *group;

	password_dialog = GNOME_TWO_PASSWORD_DIALOG (gtk_widget_new (gnome_two_password_dialog_get_type (), NULL));
	dialog = GTK_DIALOG (password_dialog);

	gtk_window_set_title (GTK_WINDOW (password_dialog), dialog_title);
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);

	gtk_dialog_add_buttons (dialog,
				GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
				GTK_STOCK_OK, GTK_RESPONSE_OK,
				NULL);
	gtk_dialog_set_default_response (GTK_DIALOG (password_dialog), GTK_RESPONSE_OK);

	/* Setup the dialog */
	gtk_dialog_set_has_separator (dialog, FALSE);
        gtk_container_set_border_width (GTK_CONTAINER (dialog), 5);
        gtk_box_set_spacing (GTK_BOX (dialog->vbox), 2); /* 2 * 5 + 2 = 12 */
        gtk_container_set_border_width (GTK_CONTAINER (dialog->action_area), 5);
        gtk_box_set_spacing (GTK_BOX (dialog->action_area), 6);

 	gtk_window_set_position (GTK_WINDOW (password_dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_modal (GTK_WINDOW (password_dialog), TRUE);

	g_signal_connect (password_dialog, "show",
			  G_CALLBACK (dialog_show_callback), password_dialog);
	g_signal_connect (password_dialog, "close",
			  G_CALLBACK (dialog_close_callback), password_dialog);

	/* the radio buttons for anonymous login */
	password_dialog->details->connect_with_no_userpass_button =
                gtk_radio_button_new_with_mnemonic (NULL, _("Connect _anonymously"));
	group = gtk_radio_button_get_group (
			GTK_RADIO_BUTTON (password_dialog->details->connect_with_no_userpass_button));
        password_dialog->details->connect_with_userpass_button =
                gtk_radio_button_new_with_mnemonic (
			group, _("Connect as _user:"));

	if (username != NULL && *username != 0) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (password_dialog->details->connect_with_userpass_button), TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (password_dialog->details->connect_with_no_userpass_button), TRUE);
	}
	
	password_dialog->details->radio_vbox = gtk_vbox_new (FALSE, 6);
	gtk_box_pack_start (GTK_BOX (password_dialog->details->radio_vbox),
		password_dialog->details->connect_with_no_userpass_button,
		FALSE, FALSE, 0);	
	gtk_box_pack_start (GTK_BOX (password_dialog->details->radio_vbox),
                password_dialog->details->connect_with_userpass_button,
                FALSE, FALSE, 0);
	g_signal_connect (password_dialog->details->connect_with_no_userpass_button, "clicked",
                          G_CALLBACK (userpass_radio_button_clicked), password_dialog);
	g_signal_connect (password_dialog->details->connect_with_userpass_button, "clicked",
                          G_CALLBACK (userpass_radio_button_clicked), password_dialog);	

	/* The table that holds the captions */
	password_dialog->details->table_alignment = gtk_alignment_new (0.0, 0.0, 0.0, 0.0);

	password_dialog->details->table = table = gtk_table_new (3, 2, FALSE);
	gtk_table_set_col_spacings (GTK_TABLE (table), 12);
	gtk_table_set_row_spacings (GTK_TABLE (table), 6);
	gtk_container_add (GTK_CONTAINER (password_dialog->details->table_alignment), table);

	password_dialog->details->username_entry = gtk_entry_new ();
	password_dialog->details->domain_entry = gtk_entry_new ();
	password_dialog->details->password_entry = gtk_entry_new ();
	password_dialog->details->password_entry_secondary = gtk_entry_new ();

	/* We want to hold on to these during the table rearrangement */
#if GLIB_CHECK_VERSION (2, 10, 0)
	g_object_ref_sink (password_dialog->details->username_entry);
	g_object_ref_sink (password_dialog->details->domain_entry);
        g_object_ref_sink (password_dialog->details->password_entry);
        g_object_ref_sink (password_dialog->details->password_entry_secondary);
#else
	g_object_ref (password_dialog->details->username_entry);
	gtk_object_sink (GTK_OBJECT (password_dialog->details->username_entry));
	g_object_ref (password_dialog->details->domain_entry);
	gtk_object_sink (GTK_OBJECT (password_dialog->details->domain_entry));
        g_object_ref (password_dialog->details->password_entry);
	gtk_object_sink (GTK_OBJECT (password_dialog->details->password_entry));
        g_object_ref (password_dialog->details->password_entry_secondary);
	gtk_object_sink (GTK_OBJECT (password_dialog->details->password_entry_secondary));
#endif
	
	gtk_entry_set_visibility (GTK_ENTRY (password_dialog->details->password_entry), FALSE);
	gtk_entry_set_visibility (GTK_ENTRY (password_dialog->details->password_entry_secondary), FALSE);

	g_signal_connect (password_dialog->details->username_entry,
			  "activate",
			  G_CALLBACK (username_entry_activate),
			  password_dialog);
	g_signal_connect (password_dialog->details->domain_entry,
			  "activate",
			  G_CALLBACK (domain_entry_activate),
			  password_dialog);
	g_signal_connect_swapped (password_dialog->details->password_entry,
				  "activate",
				  G_CALLBACK (gtk_window_activate_default),
				  password_dialog);
	g_signal_connect_swapped (password_dialog->details->password_entry_secondary,
				  "activate",
				  G_CALLBACK (gtk_window_activate_default),
				  password_dialog);
	add_table_rows (password_dialog);

	/* Adds some eye-candy to the dialog */
	hbox = gtk_hbox_new (FALSE, 12);
 	gtk_container_set_border_width (GTK_CONTAINER (hbox), 5);
	dialog_icon = gtk_image_new_from_stock (GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_DIALOG);
	gtk_misc_set_alignment (GTK_MISC (dialog_icon), 0.5, 0.0);
	gtk_box_pack_start (GTK_BOX (hbox), dialog_icon, FALSE, FALSE, 0);

	/* Fills the vbox */
	main_vbox = gtk_vbox_new (FALSE, 18);

	if (message) {
		message_label = GTK_LABEL (gtk_label_new (message));
		gtk_label_set_justify (message_label, GTK_JUSTIFY_LEFT);
		gtk_label_set_line_wrap (message_label, TRUE);

		gtk_box_pack_start (GTK_BOX (main_vbox), GTK_WIDGET (message_label),
				    FALSE, FALSE, 0);
	}

	vbox = gtk_vbox_new (FALSE, 6);
	gtk_box_pack_start (GTK_BOX (main_vbox), vbox, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (vbox), password_dialog->details->radio_vbox,
                            FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (vbox), password_dialog->details->table_alignment,
			    FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (hbox), main_vbox, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (GTK_DIALOG (password_dialog)->vbox),
			    hbox,
			    TRUE,	/* expand */
			    TRUE,	/* fill */
			    0);       	/* padding */
	
	gtk_widget_show_all (GTK_DIALOG (password_dialog)->vbox);

	password_dialog->details->remember_session_button =
		gtk_check_button_new_with_mnemonic (_("_Remember passwords for this session"));
	password_dialog->details->remember_forever_button =
		gtk_check_button_new_with_mnemonic (_("_Save passwords in keyring"));

	gtk_box_pack_start (GTK_BOX (vbox), password_dialog->details->remember_session_button, 
			    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (vbox), password_dialog->details->remember_forever_button, 
			    FALSE, FALSE, 0);

	gnome_two_password_dialog_set_username (password_dialog, username);
	gnome_two_password_dialog_set_password (password_dialog, password);
	gnome_two_password_dialog_set_readonly_domain (password_dialog, readonly_username);
	
	return GTK_WIDGET (password_dialog);
}

gboolean
gnome_two_password_dialog_run_and_block (GnomeTwoPasswordDialog *password_dialog)
{
	gint button_clicked;

	g_return_val_if_fail (password_dialog != NULL, FALSE);
	g_return_val_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog), FALSE);

	button_clicked = gtk_dialog_run (GTK_DIALOG (password_dialog));
	gtk_widget_hide (GTK_WIDGET (password_dialog));

	return button_clicked == GTK_RESPONSE_OK;
}

void
gnome_two_password_dialog_set_username (GnomeTwoPasswordDialog	*password_dialog,
				       const char		*username)
{
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));
	g_return_if_fail (password_dialog->details->username_entry != NULL);

	gtk_entry_set_text (GTK_ENTRY (password_dialog->details->username_entry),
			    username?username:"");
}

void
gnome_two_password_dialog_set_password (GnomeTwoPasswordDialog	*password_dialog,
				       const char		*password)
{
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));

	gtk_entry_set_text (GTK_ENTRY (password_dialog->details->password_entry),
			    password ? password : "");
}

void
gnome_two_password_dialog_set_password_secondary (GnomeTwoPasswordDialog	*password_dialog,
						  const char		        *password_secondary)
{
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));

	gtk_entry_set_text (GTK_ENTRY (password_dialog->details->password_entry_secondary),
			    password_secondary ? password_secondary : "");
}

void
gnome_two_password_dialog_set_domain (GnomeTwoPasswordDialog	*password_dialog,
				  const char		*domain)
{
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));
	g_return_if_fail (password_dialog->details->domain_entry != NULL);

	gtk_entry_set_text (GTK_ENTRY (password_dialog->details->domain_entry),
			    domain ? domain : "");
}


void
gnome_two_password_dialog_set_show_username (GnomeTwoPasswordDialog *password_dialog,
					 gboolean             show)
{
	g_return_if_fail (password_dialog != NULL);
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));

	show = !!show;
	if (password_dialog->details->show_username != show) {
		password_dialog->details->show_username = show;
		add_table_rows (password_dialog);
	}
}

void
gnome_two_password_dialog_set_show_domain (GnomeTwoPasswordDialog *password_dialog,
				       gboolean             show)
{
	g_return_if_fail (password_dialog != NULL);
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));

	show = !!show;
	if (password_dialog->details->show_domain != show) {
		password_dialog->details->show_domain = show;
		add_table_rows (password_dialog);
	}
}

void
gnome_two_password_dialog_set_show_password (GnomeTwoPasswordDialog *password_dialog,
					 gboolean             show)
{
	g_return_if_fail (password_dialog != NULL);
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));

	show = !!show;
	if (password_dialog->details->show_password != show) {
		password_dialog->details->show_password = show;
		add_table_rows (password_dialog);
	}
}

void
gnome_two_password_dialog_set_show_password_secondary (GnomeTwoPasswordDialog *password_dialog,
						       gboolean             show)
{
	g_return_if_fail (password_dialog != NULL);
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));

	show = !!show;
	if (password_dialog->details->show_password_secondary != show) {
		password_dialog->details->show_password_secondary = show;
		add_table_rows (password_dialog);
	}
}

void
gnome_two_password_dialog_set_readonly_username (GnomeTwoPasswordDialog	*password_dialog,
						gboolean		readonly)
{
	g_return_if_fail (password_dialog != NULL);
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));

	password_dialog->details->readonly_username = readonly;

	gtk_widget_set_sensitive (password_dialog->details->username_entry,
				  !readonly);
}

void
gnome_two_password_dialog_set_readonly_domain (GnomeTwoPasswordDialog	*password_dialog,
					   gboolean		readonly)
{
	g_return_if_fail (password_dialog != NULL);
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));

	password_dialog->details->readonly_domain = readonly;

	gtk_widget_set_sensitive (password_dialog->details->domain_entry,
				  !readonly);
}

char *
gnome_two_password_dialog_get_username (GnomeTwoPasswordDialog *password_dialog)
{
	g_return_val_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog), NULL);

	return g_strdup (gtk_entry_get_text (GTK_ENTRY (password_dialog->details->username_entry)));
}

char *
gnome_two_password_dialog_get_domain (GnomeTwoPasswordDialog *password_dialog)
{
	g_return_val_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog), NULL);
	
	return g_strdup (gtk_entry_get_text (GTK_ENTRY (password_dialog->details->domain_entry)));
}

char *
gnome_two_password_dialog_get_password (GnomeTwoPasswordDialog *password_dialog)
{
	g_return_val_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog), NULL);

	return g_strdup (gtk_entry_get_text (GTK_ENTRY (password_dialog->details->password_entry)));
}

char *
gnome_two_password_dialog_get_password_secondary (GnomeTwoPasswordDialog *password_dialog)
{
	g_return_val_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog), NULL);

	return g_strdup (gtk_entry_get_text (GTK_ENTRY (password_dialog->details->password_entry_secondary)));
}

void
gnome_two_password_dialog_set_show_userpass_buttons (GnomeTwoPasswordDialog         *password_dialog,
						     gboolean                     show_userpass_buttons)
{
        if (show_userpass_buttons) {
                password_dialog->details->anon_support_on = TRUE;
                gtk_widget_show (password_dialog->details->radio_vbox);
                if (gtk_toggle_button_get_active (
                        GTK_TOGGLE_BUTTON (password_dialog->details->connect_with_no_userpass_button))) {
                        gtk_widget_set_sensitive (password_dialog->details->table, FALSE);
                }
                else {
                        gtk_widget_set_sensitive (password_dialog->details->table, TRUE);
                }
        } else {
                password_dialog->details->anon_support_on = FALSE;
                gtk_widget_hide (password_dialog->details->radio_vbox);
                gtk_widget_set_sensitive (password_dialog->details->table, TRUE);
        }
                                                                                                                             
        add_table_rows (password_dialog);
}

gboolean
gnome_two_password_dialog_anon_selected (GnomeTwoPasswordDialog *password_dialog)
{
	return password_dialog->details->anon_support_on &&
		gtk_toggle_button_get_active (
        		GTK_TOGGLE_BUTTON (
				password_dialog->details->connect_with_no_userpass_button));
}

void
gnome_two_password_dialog_set_show_remember (GnomeTwoPasswordDialog         *password_dialog,
					 gboolean                     show_remember)
{
	if (show_remember) {
		gtk_widget_show (password_dialog->details->remember_session_button);
		gtk_widget_show (password_dialog->details->remember_forever_button);
	} else {
		gtk_widget_hide (password_dialog->details->remember_session_button);
		gtk_widget_hide (password_dialog->details->remember_forever_button);
	}
}

void
gnome_two_password_dialog_set_remember      (GnomeTwoPasswordDialog         *password_dialog,
					 GnomeTwoPasswordDialogRemember  remember)
{
	gboolean session, forever;

	session = FALSE;
	forever = FALSE;
	if (remember == GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION) {
		session = TRUE;
	} else if (remember == GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER){
		forever = TRUE;
	}
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (password_dialog->details->remember_session_button),
				      session);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (password_dialog->details->remember_forever_button),
				      forever);
}

GnomeTwoPasswordDialogRemember
gnome_two_password_dialog_get_remember (GnomeTwoPasswordDialog         *password_dialog)
{
	gboolean session, forever;

	session = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (password_dialog->details->remember_session_button));
	forever = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (password_dialog->details->remember_forever_button));
	if (forever) {
		return GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER;
	} else if (session) {
		return GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION;
	}
	return GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING;
}

void gnome_two_password_dialog_set_password_secondary_label (GnomeTwoPasswordDialog  *password_dialog,
							     const char              *password_secondary_label)
{
	g_return_if_fail (password_dialog != NULL);
	g_return_if_fail (GNOME_IS_TWO_PASSWORD_DIALOG (password_dialog));

	g_free (password_dialog->details->secondary_password_label);
	password_dialog->details->secondary_password_label = g_strdup (password_secondary_label);

	if (password_dialog->details->show_password_secondary) {
		add_table_rows (password_dialog);
	}
}
