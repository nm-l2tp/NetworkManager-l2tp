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

#include <string.h>
#include <gnome-keyring-memory.h>

#include <nm-setting-vpn.h>

#include "keyring-helpers.h"
#include "../src/nm-l2tp-service.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

char *
keyring_helpers_lookup_secret (const char *vpn_uuid,
                   const char *secret_name,
                   gboolean *is_session)
{
	GList *found_list = NULL;
	GnomeKeyringResult ret;
	GnomeKeyringFound *found;
	char *secret;

	ret = gnome_keyring_find_itemsv_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      &found_list,
	                                      KEYRING_UUID_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      vpn_uuid,
	                                      KEYRING_SN_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      NM_SETTING_VPN_SETTING_NAME,
	                                      KEYRING_SK_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      secret_name,
	                                      NULL);
	if ((ret != GNOME_KEYRING_RESULT_OK) || (g_list_length (found_list) == 0))
		return NULL;

	found = (GnomeKeyringFound *) found_list->data;

	if (is_session) {
		if (strcmp (found->keyring, "session") == 0)
			*is_session = TRUE;
		else
			*is_session = FALSE;
	}

	secret = found->secret ? gnome_keyring_memory_strdup (found->secret) : NULL;
	gnome_keyring_found_list_free (found_list);

	return secret;
}

GnomeKeyringResult
keyring_helpers_save_secret (const char *vpn_uuid,
                             const char *vpn_name,
                             const char *keyring,
                             const char *secret_name,
                             const char *secret)
{
	char *display_name;
	GnomeKeyringResult ret;
	GnomeKeyringAttributeList *attrs = NULL;
	guint32 id = 0;

	display_name = g_strdup_printf ("VPN %s secret for %s/%s/" NM_SETTING_VPN_SETTING_NAME,
	                                secret_name,
	                                vpn_name,
	                                NM_DBUS_SERVICE_L2TP);

	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs,
	                                            KEYRING_UUID_TAG,
	                                            vpn_uuid);
	gnome_keyring_attribute_list_append_string (attrs,
	                                            KEYRING_SN_TAG,
	                                            NM_SETTING_VPN_SETTING_NAME);
	gnome_keyring_attribute_list_append_string (attrs,
	                                            KEYRING_SK_TAG,
	                                            secret_name);

	ret = gnome_keyring_item_create_sync (keyring,
	                                      GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      display_name,
	                                      attrs,
	                                      secret,
	                                      TRUE,
	                                      &id);
	gnome_keyring_attribute_list_free (attrs);
	g_free (display_name);
	return ret;
}

static void
ignore_callback (GnomeKeyringResult result, gpointer data)
{
}

gboolean
keyring_helpers_delete_secret (const char *vpn_uuid,
                               const char *secret_name)
{
	GList *found = NULL, *iter;
	GnomeKeyringResult ret;

	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (secret_name != NULL, FALSE);

	ret = gnome_keyring_find_itemsv_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      &found,
	                                      KEYRING_UUID_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      vpn_uuid,
	                                      KEYRING_SN_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      NM_SETTING_VPN_SETTING_NAME,
	                                      KEYRING_SK_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      secret_name,
	                                      NULL);
	if (ret != GNOME_KEYRING_RESULT_OK && ret != GNOME_KEYRING_RESULT_NO_MATCH)
		return FALSE;
	if (g_list_length (found) == 0)
		return TRUE;

	/* delete them all */
	for (iter = found; iter; iter = g_list_next (iter)) {
		GnomeKeyringFound *item = (GnomeKeyringFound *) iter->data;

		gnome_keyring_item_delete (item->keyring, item->item_id,
		                           ignore_callback, NULL, NULL);
	}

	gnome_keyring_found_list_free (found);
	return TRUE;
}

