/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2016 Red Hat, Inc.
 */

#ifndef __NM_SHARED_UTILS_H__
#define __NM_SHARED_UTILS_H__

/******************************************************************************/

gint64 _nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback);

gint _nm_utils_ascii_str_to_bool (const char *str,
                                  gint default_value);

/******************************************************************************/

/**
 * NMUtilsError:
 * @NM_UTILS_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_UTILS_ERROR_CANCELLED_DISPOSING: when disposing an object that has
 *   pending aynchronous operations, the operation is cancelled with this
 *   error reason. Depending on the usage, this might indicate a bug because
 *   usually the target object should stay alive as long as there are pending
 *   operations.
 */
typedef enum {
	NM_UTILS_ERROR_UNKNOWN = 0,                 /*< nick=Unknown >*/
	NM_UTILS_ERROR_CANCELLED_DISPOSING,         /*< nick=CancelledDisposing >*/
} NMUtilsError;

#define NM_UTILS_ERROR (nm_utils_error_quark ())
GQuark nm_utils_error_quark (void);

void nm_utils_error_set_cancelled (GError **error,
                                   gboolean is_disposing,
                                   const char *instance_name);
gboolean nm_utils_error_is_cancelled (GError *error,
                                      gboolean consider_is_disposing);

/******************************************************************************/

gboolean nm_g_object_set_property (GObject *object,
                                   const gchar  *property_name,
                                   const GValue *value,
                                   GError **error);

/******************************************************************************/

#endif /* __NM_SHARED_UTILS_H__ */
