/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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

#ifndef _NM_L2TP_EDITOR_H_
#define _NM_L2TP_EDITOR_H_

#define L2TP_TYPE_PLUGIN_UI_WIDGET            (l2tp_plugin_ui_widget_get_type ())
#define L2TP_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), L2TP_TYPE_PLUGIN_UI_WIDGET, L2tpPluginUiWidget))
#define L2TP_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), L2TP_TYPE_PLUGIN_UI_WIDGET, L2tpPluginUiWidgetClass))
#define L2TP_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), L2TP_TYPE_PLUGIN_UI_WIDGET))
#define L2TP_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), L2TP_TYPE_PLUGIN_UI_WIDGET))
#define L2TP_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), L2TP_TYPE_PLUGIN_UI_WIDGET, L2tpPluginUiWidgetClass))

typedef struct _L2tpPluginUiWidget L2tpPluginUiWidget;
typedef struct _L2tpPluginUiWidgetClass L2tpPluginUiWidgetClass;

struct _L2tpPluginUiWidget {
	GObject parent;
};

struct _L2tpPluginUiWidgetClass {
	GObjectClass parent;
};

GType l2tp_plugin_ui_widget_get_type (void);

NMVpnEditor *nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error);

#endif	/* _NM_L2TP_EDITOR_H_ */

