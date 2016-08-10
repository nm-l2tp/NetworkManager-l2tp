/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-l2tp-service - L2TP VPN integration with NetworkManager
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
