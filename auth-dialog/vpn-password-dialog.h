/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* vpn-password-dialog.c - A use password prompting dialog widget.
 *
 * The Gnome Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the ree Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * The Gnome Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 1999, 2000 Eazel, Inc.
 * Copyright (C) 2011 Red Hat, Inc.
 *
 * Authors: Ramiro Estrugo <ramiro@eazel.com>
 *          Dan Williams <dcbw@redhat.com>
 */

#ifndef VPN_PASSWORD_DIALOG_H
#define VPN_PASSWORD_DIALOG_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define VPN_TYPE_PASSWORD_DIALOG            (vpn_password_dialog_get_type ())
#define VPN_PASSWORD_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), VPN_TYPE_PASSWORD_DIALOG, VpnPasswordDialog))
#define VPN_PASSWORD_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), VPN_TYPE_PASSWORD_DIALOG, VpnPasswordDialogClass))
#define VPN_IS_PASSWORD_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), VPN_TYPE_PASSWORD_DIALOG))
#define VPN_IS_PASSWORD_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), VPN_TYPE_PASSWORD_DIALOG))

typedef struct VpnPasswordDialog        VpnPasswordDialog;
typedef struct VpnPasswordDialogClass   VpnPasswordDialogClass;

struct VpnPasswordDialog {
	GtkDialog parent;
};

struct VpnPasswordDialogClass {
	GtkDialogClass parent_class;
};

GType      vpn_password_dialog_get_type              (void);
GtkWidget* vpn_password_dialog_new                   (const char *title,
                                                      const char *message,
                                                      const char *password);

gboolean   vpn_password_dialog_run_and_block         (VpnPasswordDialog *dialog);

/* Attribute mutators */
void vpn_password_dialog_set_show_password            (VpnPasswordDialog *dialog,
                                                       gboolean show);
void vpn_password_dialog_focus_password               (VpnPasswordDialog *dialog);
void vpn_password_dialog_set_password                 (VpnPasswordDialog *dialog,
                                                       const char *password);
void vpn_password_dialog_set_password_label           (VpnPasswordDialog *dialog,
                                                       const char *label);

void vpn_password_dialog_set_show_password_secondary  (VpnPasswordDialog *dialog,
                                                       gboolean show);
void vpn_password_dialog_focus_password_secondary     (VpnPasswordDialog *dialog);
void vpn_password_dialog_set_password_secondary       (VpnPasswordDialog *dialog,
                                                       const char *password_secondary);
void vpn_password_dialog_set_password_secondary_label (VpnPasswordDialog *dialog,
                                                       const char *label);
/* Attribute accessors */
const char *vpn_password_dialog_get_password                (VpnPasswordDialog *dialog);

const char *vpn_password_dialog_get_password_secondary      (VpnPasswordDialog *dialog);

G_END_DECLS

#endif /* VPN_PASSWORD_DIALOG_H */
