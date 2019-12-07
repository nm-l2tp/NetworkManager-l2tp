/*
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
 * Copyright 2016 Red Hat, Inc.
 */

#ifndef __NM_VPN_PLUGIN_UTILS_H__
#define __NM_VPN_PLUGIN_UTILS_H__

#include <NetworkManager.h>

typedef NMVpnEditor *(NMVpnPluginUtilsEditorFactory) (gpointer factory,
                                                      NMVpnEditorPlugin *editor_plugin,
                                                      NMConnection *connection,
                                                      gpointer user_data,
                                                      GError **error);

NMVpnEditor *nm_vpn_plugin_utils_load_editor (const char *module_name,
                                              const char *factory_name,
                                              NMVpnPluginUtilsEditorFactory editor_factory,
                                              NMVpnEditorPlugin *editor_plugin,
                                              NMConnection *connection,
                                              gpointer user_data,
                                              GError **error);

#endif /* __NM_VPN_PLUGIN_UTILS_H__ */

