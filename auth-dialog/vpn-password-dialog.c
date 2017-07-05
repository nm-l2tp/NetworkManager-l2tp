/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nma-vpn-password-dialog.c - A password prompting dialog widget.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the ree Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 1999, 2000 Eazel, Inc.
 * Copyright (C) 2011, 2013 Red Hat, Inc.
 *
 * Authors: Ramiro Estrugo <ramiro@eazel.com>
 *          Dan Williams <dcbw@redhat.com>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include "vpn-password-dialog.h"

G_DEFINE_TYPE (NMAVpnPasswordDialog, nma_vpn_password_dialog, GTK_TYPE_DIALOG)

#define NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                NMA_VPN_TYPE_PASSWORD_DIALOG, \
                                                NMAVpnPasswordDialogPrivate))

typedef struct {
	/* Attributes */
	gboolean show_password;
	gboolean show_password_secondary;
	gboolean show_password_ternary;

	/* Internal widgetry and flags */
	GtkWidget *password_entry;
	GtkWidget *password_entry_secondary;
	GtkWidget *password_entry_ternary;
	GtkWidget *show_passwords_checkbox;

	GtkWidget *grid_alignment;
	GtkWidget *grid;
	GtkSizeGroup *group;

	char *primary_password_label;
	char *secondary_password_label;
	char *ternary_password_label;
} NMAVpnPasswordDialogPrivate;

/* NMAVpnPasswordDialogClass methods */
static void nma_vpn_password_dialog_class_init (NMAVpnPasswordDialogClass *password_dialog_class);
static void nma_vpn_password_dialog_init       (NMAVpnPasswordDialog      *password_dialog);

/* GtkDialog callbacks */
static void dialog_show_callback (GtkWidget *widget, gpointer callback_data);
static void dialog_close_callback (GtkWidget *widget, gpointer callback_data);

static void
finalize (GObject *object)
{
	NMAVpnPasswordDialogPrivate *priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (object);
	
	g_object_unref (priv->password_entry);
	g_object_unref (priv->password_entry_secondary);
	g_object_unref (priv->password_entry_ternary);
	g_object_unref (priv->group);

	g_free (priv->primary_password_label);
	g_free (priv->secondary_password_label);
	g_free (priv->ternary_password_label);

	G_OBJECT_CLASS (nma_vpn_password_dialog_parent_class)->finalize (object);
}

static void
nma_vpn_password_dialog_class_init (NMAVpnPasswordDialogClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMAVpnPasswordDialogPrivate));

	object_class->finalize = finalize;
}

static void
nma_vpn_password_dialog_init (NMAVpnPasswordDialog *dialog)
{
	NMAVpnPasswordDialogPrivate *priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	priv->show_password = TRUE;
	priv->primary_password_label = g_strdup ( _("_Password:") );
	priv->show_password_secondary = TRUE;
	priv->secondary_password_label = g_strdup ( _("_Secondary Password:") );
	/* Make ternary password entry hidden by default */
	priv->show_password_ternary = FALSE;
	priv->ternary_password_label = g_strdup ( _("_Tertiary Password:") );
}

/* GtkDialog callbacks */
static void
dialog_show_callback (GtkWidget *widget, gpointer callback_data)
{
	NMAVpnPasswordDialog *dialog = NMA_VPN_PASSWORD_DIALOG (callback_data);
	NMAVpnPasswordDialogPrivate *priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	if (gtk_widget_get_visible (priv->password_entry))
		gtk_widget_grab_focus (priv->password_entry);
	else if (gtk_widget_get_visible (priv->password_entry_secondary))
		gtk_widget_grab_focus (priv->password_entry_secondary);
	else if (gtk_widget_get_visible (priv->password_entry_ternary))
		gtk_widget_grab_focus (priv->password_entry_ternary);
}

static void
dialog_close_callback (GtkWidget *widget, gpointer callback_data)
{
	gtk_widget_hide (widget);
}

static void
add_row (GtkWidget *grid, int row, const char *label_text, GtkWidget *entry)
{
	GtkWidget *label;

	label = gtk_label_new_with_mnemonic (label_text);
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);

	gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), entry, 1, row, 1, 1);

	gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);
}

static void
remove_child (GtkWidget *child, GtkWidget *grid)
{
	gtk_container_remove (GTK_CONTAINER (grid), child);
}

static void
add_grid_rows (NMAVpnPasswordDialog *dialog)
{
	NMAVpnPasswordDialogPrivate *priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	int row;
	int offset = 0;

	gtk_alignment_set_padding (GTK_ALIGNMENT (priv->grid_alignment), 0, 0, offset, 0);

	/* This will not kill the entries, since they are ref:ed */
	gtk_container_foreach (GTK_CONTAINER (priv->grid), (GtkCallback) remove_child, priv->grid);
	
	row = 0;
	if (priv->show_password)
		add_row (priv->grid, row++, priv->primary_password_label, priv->password_entry);
	if (priv->show_password_secondary)
		add_row (priv->grid, row++, priv->secondary_password_label,  priv->password_entry_secondary);
	if (priv->show_password_ternary)
		add_row (priv->grid, row++, priv->ternary_password_label,  priv->password_entry_ternary);

	gtk_grid_attach (GTK_GRID (priv->grid), priv->show_passwords_checkbox, 1, row, 1, 1);

	gtk_widget_show_all (priv->grid);
}

static void
show_passwords_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	NMAVpnPasswordDialog *dialog = NMA_VPN_PASSWORD_DIALOG (user_data);
	NMAVpnPasswordDialogPrivate *priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry), visible);
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry_secondary), visible);
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry_ternary), visible);
}

/* Public NMAVpnPasswordDialog methods */
GtkWidget *
nma_vpn_password_dialog_new (const char *title,
                             const char *message,
                             const char *password)
{
	GtkWidget *dialog;
	NMAVpnPasswordDialogPrivate *priv;
	GtkLabel *message_label;
	GtkWidget *hbox;
	GtkWidget *vbox;
	GtkWidget *main_vbox;
	GtkWidget *dialog_icon;
	GtkBox *content, *action_area;

	dialog = gtk_widget_new (NMA_VPN_TYPE_PASSWORD_DIALOG, NULL);
	if (!dialog)
		return NULL;
	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	gtk_window_set_title (GTK_WINDOW (dialog), title);
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);

	gtk_dialog_add_buttons (GTK_DIALOG (dialog),
	                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
	                        GTK_STOCK_OK, GTK_RESPONSE_OK,
	                        NULL);
	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);

	content = GTK_BOX (gtk_dialog_get_content_area (GTK_DIALOG (dialog)));
	action_area = GTK_BOX (gtk_dialog_get_action_area (GTK_DIALOG (dialog)));

	/* Set up the dialog */
	gtk_container_set_border_width (GTK_CONTAINER (dialog), 5);
	gtk_box_set_spacing (content, 2); /* 2 * 5 + 2 = 12 */
	gtk_container_set_border_width (GTK_CONTAINER (action_area), 5);
	gtk_box_set_spacing (action_area, 6);

 	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_signal_connect (dialog, "show",
	                  G_CALLBACK (dialog_show_callback),
	                  dialog);
	g_signal_connect (dialog, "close",
	                  G_CALLBACK (dialog_close_callback),
	                  dialog);

	/* The grid that holds the captions */
	priv->grid_alignment = gtk_alignment_new (0.0, 0.0, 0.0, 0.0);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	priv->grid = gtk_grid_new ();
	gtk_grid_set_column_spacing (GTK_GRID (priv->grid), 12);
	gtk_grid_set_row_spacing (GTK_GRID (priv->grid), 6);
	gtk_container_add (GTK_CONTAINER (priv->grid_alignment), priv->grid);

	priv->password_entry = gtk_entry_new ();
	priv->password_entry_secondary = gtk_entry_new ();
	priv->password_entry_ternary = gtk_entry_new ();

	priv->show_passwords_checkbox = gtk_check_button_new_with_mnemonic (_("Sh_ow passwords"));

	/* We want to hold on to these during the grid rearrangement */
	g_object_ref_sink (priv->password_entry);
	g_object_ref_sink (priv->password_entry_secondary);
	g_object_ref_sink (priv->password_entry_ternary);
	g_object_ref_sink (priv->show_passwords_checkbox);
	
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry), FALSE);
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry_secondary), FALSE);
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry_ternary), FALSE);

	g_signal_connect_swapped (priv->password_entry, "activate",
	                          G_CALLBACK (gtk_window_activate_default),
	                          dialog);
	g_signal_connect_swapped (priv->password_entry_secondary, "activate",
	                          G_CALLBACK (gtk_window_activate_default),
	                          dialog);
	g_signal_connect_swapped (priv->password_entry_ternary, "activate",
	                          G_CALLBACK (gtk_window_activate_default),
	                          dialog);

	g_signal_connect (priv->show_passwords_checkbox, "toggled",
	                  G_CALLBACK (show_passwords_toggled_cb),
	                  dialog);

	add_grid_rows (NMA_VPN_PASSWORD_DIALOG (dialog));

	/* Adds some eye-candy to the dialog */
	hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
 	gtk_container_set_border_width (GTK_CONTAINER (hbox), 5);
	dialog_icon = gtk_image_new_from_stock (GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_DIALOG);
	gtk_misc_set_alignment (GTK_MISC (dialog_icon), 0.5, 0.0);
	gtk_box_pack_start (GTK_BOX (hbox), dialog_icon, FALSE, FALSE, 0);

	/* Fills the vbox */
	main_vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 18);

	if (message) {
		message_label = GTK_LABEL (gtk_label_new (message));
		gtk_label_set_justify (message_label, GTK_JUSTIFY_LEFT);
		gtk_label_set_line_wrap (message_label, TRUE);
		gtk_label_set_max_width_chars (message_label, 35);
		gtk_size_group_add_widget (priv->group, GTK_WIDGET (message_label));
		gtk_box_pack_start (GTK_BOX (main_vbox), GTK_WIDGET (message_label), FALSE, FALSE, 0);
		gtk_size_group_add_widget (priv->group, priv->grid_alignment);
	}

	vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	gtk_box_pack_start (GTK_BOX (main_vbox), vbox, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (vbox), priv->grid_alignment, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (hbox), main_vbox, FALSE, FALSE, 0);
	gtk_box_pack_start (content, hbox, FALSE, FALSE, 0);
	gtk_widget_show_all (GTK_WIDGET (content));

	nma_vpn_password_dialog_set_password (NMA_VPN_PASSWORD_DIALOG (dialog), password);
	
	return GTK_WIDGET (dialog);
}

gboolean
nma_vpn_password_dialog_run_and_block (NMAVpnPasswordDialog *dialog)
{
	gint button_clicked;

	g_return_val_if_fail (dialog != NULL, FALSE);
	g_return_val_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog), FALSE);

	button_clicked = gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_hide (GTK_WIDGET (dialog));

	return button_clicked == GTK_RESPONSE_OK;
}

void
nma_vpn_password_dialog_set_password (NMAVpnPasswordDialog	*dialog,
                                      const char *password)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	gtk_entry_set_text (GTK_ENTRY (priv->password_entry), password ? password : "");
}

void
nma_vpn_password_dialog_set_password_secondary (NMAVpnPasswordDialog *dialog,
                                                const char *password_secondary)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	gtk_entry_set_text (GTK_ENTRY (priv->password_entry_secondary),
	                    password_secondary ? password_secondary : "");
}

void
nma_vpn_password_dialog_set_password_ternary (NMAVpnPasswordDialog *dialog,
                                              const char *password_ternary)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	gtk_entry_set_text (GTK_ENTRY (priv->password_entry_ternary),
	                    password_ternary ? password_ternary : "");
}

void
nma_vpn_password_dialog_set_show_password (NMAVpnPasswordDialog *dialog, gboolean show)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	show = !!show;
	if (priv->show_password != show) {
		priv->show_password = show;
		add_grid_rows (dialog);
	}
}

void
nma_vpn_password_dialog_set_show_password_secondary (NMAVpnPasswordDialog *dialog,
                                                     gboolean show)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	show = !!show;
	if (priv->show_password_secondary != show) {
		priv->show_password_secondary = show;
		add_grid_rows (dialog);
	}
}

void
nma_vpn_password_dialog_set_show_password_ternary (NMAVpnPasswordDialog *dialog,
                                                   gboolean show)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	show = !!show;
	if (priv->show_password_ternary != show) {
		priv->show_password_ternary = show;
		add_grid_rows (dialog);
	}
}

void
nma_vpn_password_dialog_focus_password (NMAVpnPasswordDialog *dialog)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	if (priv->show_password)
		gtk_widget_grab_focus (priv->password_entry);
}

void
nma_vpn_password_dialog_focus_password_secondary (NMAVpnPasswordDialog *dialog)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	if (priv->show_password_secondary)
		gtk_widget_grab_focus (priv->password_entry_secondary);
}

void
nma_vpn_password_dialog_focus_password_ternary (NMAVpnPasswordDialog *dialog)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	if (priv->show_password_ternary)
		gtk_widget_grab_focus (priv->password_entry_ternary);
}

const char *
nma_vpn_password_dialog_get_password (NMAVpnPasswordDialog *dialog)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_val_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog), NULL);

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	return gtk_entry_get_text (GTK_ENTRY (priv->password_entry));
}

const char *
nma_vpn_password_dialog_get_password_secondary (NMAVpnPasswordDialog *dialog)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_val_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog), NULL);

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	return gtk_entry_get_text (GTK_ENTRY (priv->password_entry_secondary));
}

const char *
nma_vpn_password_dialog_get_password_ternary (NMAVpnPasswordDialog *dialog)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_val_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog), NULL);

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	return gtk_entry_get_text (GTK_ENTRY (priv->password_entry_ternary));
}

void nma_vpn_password_dialog_set_password_label (NMAVpnPasswordDialog *dialog,
                                                 const char *label)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	g_free (priv->primary_password_label);
	priv->primary_password_label = g_strdup (label);

	if (priv->show_password)
		add_grid_rows (dialog);
}

void nma_vpn_password_dialog_set_password_secondary_label (NMAVpnPasswordDialog *dialog,
                                                           const char *label)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	g_free (priv->secondary_password_label);
	priv->secondary_password_label = g_strdup (label);

	if (priv->show_password_secondary)
		add_grid_rows (dialog);
}

void nma_vpn_password_dialog_set_password_ternary_label (NMAVpnPasswordDialog *dialog,
                                                         const char *label)
{
	NMAVpnPasswordDialogPrivate *priv;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (NMA_VPN_IS_PASSWORD_DIALOG (dialog));

	priv = NMA_VPN_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	g_free (priv->ternary_password_label);
	priv->ternary_password_label = g_strdup (label);

	if (priv->show_password_ternary)
		add_grid_rows (dialog);
}

