// SPDX-License-Identifier: GPL-2.0+
/***************************************************************************
 *
 * Copyright (C) 2011 Geo Carncross, <geocar@gmail.com>
 *
 */

#ifndef _IPSEC_DIALOG_H_
#define _IPSEC_DIALOG_H_

#include <glib.h>
#include <gtk/gtk.h>

#include <nm-connection.h>

GtkWidget *ipsec_dialog_new (GHashTable *hash);

GHashTable *ipsec_dialog_new_hash_from_connection (NMConnection *connection, GError **error);

GHashTable *ipsec_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error);

#endif
