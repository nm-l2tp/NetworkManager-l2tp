/* SPDX-License-Identifier: GPL-2.0-or-later */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 *
 */

#ifndef _PPP_DIALOG_H_
#define _PPP_DIALOG_H_

#include <gtk/gtk.h>

GtkWidget *ppp_dialog_new(GHashTable *hash, const char *authtype);

GHashTable *ppp_dialog_new_hash_from_connection(NMConnection *connection, GError **error);

GHashTable *ppp_dialog_new_hash_from_dialog(GtkWidget *dialog, GError **error);

#endif
