/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */

/* gnome-two-password-dialog.h - A use password prompting dialog widget
                                 asking for two passwords. Based of
                                 gnome-password-dialog.[ch] from libgnomeui

   Copyright (C) 1999, 2000 Eazel, Inc.
   Copyright (C) 2005, Red Hat, Inc.

   The Gnome Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
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

#ifndef GNOME_TWO_PASSWORD_DIALOG_H
#define GNOME_TWO_PASSWORD_DIALOG_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define GNOME_TYPE_TWO_PASSWORD_DIALOG            (gnome_two_password_dialog_get_type ())
#define GNOME_TWO_PASSWORD_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GNOME_TYPE_TWO_PASSWORD_DIALOG, GnomeTwoPasswordDialog))
#define GNOME_TWO_PASSWORD_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GNOME_TYPE_TWO_PASSWORD_DIALOG, GnomeTwoPasswordDialogClass))
#define GNOME_IS_TWO_PASSWORD_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GNOME_TYPE_TWO_PASSWORD_DIALOG))
#define GNOME_IS_TWO_PASSWORD_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GNOME_TYPE_TWO_PASSWORD_DIALOG))

typedef struct GnomeTwoPasswordDialog        GnomeTwoPasswordDialog;
typedef struct GnomeTwoPasswordDialogClass   GnomeTwoPasswordDialogClass;
typedef struct GnomeTwoPasswordDialogDetails GnomeTwoPasswordDialogDetails;

struct GnomeTwoPasswordDialog
{
	GtkDialog gtk_dialog;

	GnomeTwoPasswordDialogDetails *details;
};

struct GnomeTwoPasswordDialogClass
{
	GtkDialogClass parent_class;
};

typedef enum {
	GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING,
	GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION,
	GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER
} GnomeTwoPasswordDialogRemember;


GType    gnome_two_password_dialog_get_type (void);
GtkWidget* gnome_two_password_dialog_new      (const char *dialog_title,
					   const char *message,
					   const char *username,
					   const char *password,
					   gboolean    readonly_username);

gboolean   gnome_two_password_dialog_run_and_block           (GnomeTwoPasswordDialog *password_dialog);

/* Attribute mutators */
void gnome_two_password_dialog_set_show_username           (GnomeTwoPasswordDialog *password_dialog,
							    gboolean                show);
void gnome_two_password_dialog_set_show_domain             (GnomeTwoPasswordDialog *password_dialog,
							    gboolean                show);
void gnome_two_password_dialog_set_show_password           (GnomeTwoPasswordDialog *password_dialog,
							    gboolean                show);
void gnome_two_password_dialog_set_show_password_secondary (GnomeTwoPasswordDialog *password_dialog,
							    gboolean                show);
void gnome_two_password_dialog_set_username                (GnomeTwoPasswordDialog  *password_dialog,
							    const char              *username);
void gnome_two_password_dialog_set_domain                  (GnomeTwoPasswordDialog  *password_dialog,
							    const char              *domain);
void gnome_two_password_dialog_set_password                (GnomeTwoPasswordDialog  *password_dialog,
							    const char              *password);
void gnome_two_password_dialog_set_password_secondary      (GnomeTwoPasswordDialog  *password_dialog,
							    const char              *password_secondary);
void gnome_two_password_dialog_set_readonly_username       (GnomeTwoPasswordDialog  *password_dialog,
							    gboolean                 readonly);
void gnome_two_password_dialog_set_readonly_domain         (GnomeTwoPasswordDialog  *password_dialog,
							    gboolean                 readonly);

void gnome_two_password_dialog_set_password_secondary_label (GnomeTwoPasswordDialog  *password_dialog,
							     const char              *password_secondary_description);

void                           gnome_two_password_dialog_set_show_remember         (GnomeTwoPasswordDialog         *password_dialog,
										    gboolean                        show_remember);
void                           gnome_two_password_dialog_set_remember              (GnomeTwoPasswordDialog         *password_dialog,
										    GnomeTwoPasswordDialogRemember  remember);
GnomeTwoPasswordDialogRemember gnome_two_password_dialog_get_remember              (GnomeTwoPasswordDialog         *password_dialog);
void                           gnome_two_password_dialog_set_show_userpass_buttons (GnomeTwoPasswordDialog         *password_dialog,
										    gboolean                        show_userpass_buttons);

/* Attribute accessors */
char *     gnome_two_password_dialog_get_username            (GnomeTwoPasswordDialog *password_dialog);
char *     gnome_two_password_dialog_get_domain              (GnomeTwoPasswordDialog *password_dialog);
char *     gnome_two_password_dialog_get_password            (GnomeTwoPasswordDialog *password_dialog);
char *     gnome_two_password_dialog_get_password_secondary  (GnomeTwoPasswordDialog *password_dialog);

gboolean   gnome_two_password_dialog_anon_selected           (GnomeTwoPasswordDialog *password_dialog);

G_END_DECLS

#endif /* GNOME_TWO_PASSWORD_DIALOG_H */
