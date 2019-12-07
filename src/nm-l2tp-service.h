// SPDX-License-Identifier: GPL-2.0+
/* nm-l2tp-service - L2TP VPN integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifndef NM_L2TP_PLUGIN_H
#define NM_L2TP_PLUGIN_H

#define NM_TYPE_L2TP_PLUGIN            (nm_l2tp_plugin_get_type ())
#define NM_L2TP_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_L2TP_PLUGIN, NML2tpPlugin))
#define NM_L2TP_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_L2TP_PLUGIN, NML2tpPluginClass))
#define NM_IS_L2TP_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_L2TP_PLUGIN))
#define NM_IS_L2TP_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_L2TP_PLUGIN))
#define NM_L2TP_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_L2TP_PLUGIN, NML2tpPluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NML2tpPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NML2tpPluginClass;

GType nm_l2tp_plugin_get_type (void);

NML2tpPlugin *nm_l2tp_plugin_new (const gchar *);

#endif /* NM_L2TP_PLUGIN_H */
