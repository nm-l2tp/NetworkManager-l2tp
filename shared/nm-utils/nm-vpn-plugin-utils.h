// SPDX-License-Identifier: LGPL-2.1+
/*
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

