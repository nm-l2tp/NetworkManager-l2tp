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
 * (C) Copyright 2004 - 2008 Red Hat, Inc.
 */

#ifndef KEYRING_HELPERS_H
#define KEYRING_HELPERS_H

#include <glib.h>
#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>

char *keyring_helpers_lookup_secret (
		const char *vpn_uuid,
		const char *secret_name,
		gboolean *is_session);

GnomeKeyringResult keyring_helpers_save_secret (
		const char *vpn_uuid,
		const char *vpn_name,
		const char *keyring,
		const char *secret_name,
		const char *secret);

gboolean keyring_helpers_delete_secret (
		const char *vpn_uuid,
		const char *secret_name);

#endif  /* KEYRING_HELPERS_H */

