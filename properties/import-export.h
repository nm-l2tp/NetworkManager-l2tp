/* SPDX-License-Identifier: GPL-2.0-or-later */
/* NetworkManager-l2tp - import-export
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 */

#ifndef _IMPORT_EXPORT_H_
#define _IMPORT_EXPORT_H_

NMConnection *do_import(const char *path, GError **error);

gboolean do_export(const char *path, NMConnection *connection, GError **error);

#endif
