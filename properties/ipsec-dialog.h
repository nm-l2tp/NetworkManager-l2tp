/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2011 Geo Carncross, <geocar@gmail.com>
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
 **************************************************************************/

#ifndef _IPSEC_DIALOG_H_
#define _IPSEC_DIALOG_H_

#include <glib.h>
#include <gtk/gtk.h>

#include <nm-connection.h>

GtkWidget *ipsec_dialog_new (GHashTable *hash);

GHashTable *ipsec_dialog_new_hash_from_connection (NMConnection *connection, GError **error);

GHashTable *ipsec_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error);

#endif
