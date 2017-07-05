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
 * Copyright (C) 2011, 2013 Red Hat, Inc.
 *
 * Authors: Ramiro Estrugo <ramiro@eazel.com>
 *          Dan Williams <dcbw@redhat.com>
 */

#ifndef NMA_VPN_PASSWORD_DIALOG_H
#define NMA_VPN_PASSWORD_DIALOG_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define NMA_VPN_TYPE_PASSWORD_DIALOG            (nma_vpn_password_dialog_get_type ())
#define NMA_VPN_PASSWORD_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_VPN_TYPE_PASSWORD_DIALOG, NMAVpnPasswordDialog))
#define NMA_VPN_PASSWORD_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_VPN_TYPE_PASSWORD_DIALOG, NMAVpnPasswordDialogClass))
#define NMA_VPN_IS_PASSWORD_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_VPN_TYPE_PASSWORD_DIALOG))
#define NMA_VPN_IS_PASSWORD_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_VPN_TYPE_PASSWORD_DIALOG))

typedef struct NMAVpnPasswordDialog        NMAVpnPasswordDialog;
typedef struct NMAVpnPasswordDialogClass   NMAVpnPasswordDialogClass;

struct NMAVpnPasswordDialog {
	GtkDialog parent;
};

struct NMAVpnPasswordDialogClass {
	GtkDialogClass parent_class;
};

GType      nma_vpn_password_dialog_get_type      (void);
GtkWidget* nma_vpn_password_dialog_new           (const char *title,
                                                  const char *message,
                                                  const char *password);

gboolean   nma_vpn_password_dialog_run_and_block (NMAVpnPasswordDialog *dialog);

/* Attribute mutators */
void nma_vpn_password_dialog_set_show_password            (NMAVpnPasswordDialog *dialog,
                                                           gboolean              show);
void nma_vpn_password_dialog_focus_password               (NMAVpnPasswordDialog *dialog);
void nma_vpn_password_dialog_set_password                 (NMAVpnPasswordDialog *dialog,
                                                           const char           *password);
void nma_vpn_password_dialog_set_password_label           (NMAVpnPasswordDialog *dialog,
                                                           const char           *label);

void nma_vpn_password_dialog_set_show_password_secondary  (NMAVpnPasswordDialog *dialog,
                                                           gboolean              show);
void nma_vpn_password_dialog_focus_password_secondary     (NMAVpnPasswordDialog *dialog);
void nma_vpn_password_dialog_set_password_secondary       (NMAVpnPasswordDialog *dialog,
                                                           const char           *password_secondary);
void nma_vpn_password_dialog_set_password_secondary_label (NMAVpnPasswordDialog *dialog,
                                                           const char           *label);

void nma_vpn_password_dialog_set_show_password_ternary  (NMAVpnPasswordDialog *dialog,
                                                         gboolean              show);
void nma_vpn_password_dialog_focus_password_ternary     (NMAVpnPasswordDialog *dialog);
void nma_vpn_password_dialog_set_password_ternary       (NMAVpnPasswordDialog *dialog,
                                                         const char           *password_ternary);
void nma_vpn_password_dialog_set_password_ternary_label (NMAVpnPasswordDialog *dialog,
                                                         const char           *label);

/* Attribute accessors */
const char *nma_vpn_password_dialog_get_password           (NMAVpnPasswordDialog *dialog);

const char *nma_vpn_password_dialog_get_password_secondary (NMAVpnPasswordDialog *dialog);

const char *nma_vpn_password_dialog_get_password_ternary (NMAVpnPasswordDialog *dialog);

G_END_DECLS

#endif /* NMA_VPN_PASSWORD_DIALOG_H */
