/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-l2tp.h : GNOME UI dialogs for configuring l2tp VPN connections
 *
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

#ifndef _NM_L2TP_H_
#define _NM_L2TP_H_

#include <glib-object.h>

typedef enum
{
	L2TP_PLUGIN_UI_ERROR_UNKNOWN = 0,
	L2TP_PLUGIN_UI_ERROR_INVALID_CONNECTION,
	L2TP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
	L2TP_PLUGIN_UI_ERROR_MISSING_PROPERTY,
	L2TP_PLUGIN_UI_ERROR_FILE_NOT_READABLE,
	L2TP_PLUGIN_UI_ERROR_FILE_NOT_L2TP
} L2tpPluginUiError;

#define L2TP_TYPE_PLUGIN_UI_ERROR (l2tp_plugin_ui_error_get_type ()) 
GType l2tp_plugin_ui_error_get_type (void);

#define L2TP_PLUGIN_UI_ERROR (l2tp_plugin_ui_error_quark ())
GQuark l2tp_plugin_ui_error_quark (void);


#define L2TP_TYPE_PLUGIN_UI            (l2tp_plugin_ui_get_type ())
#define L2TP_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), L2TP_TYPE_PLUGIN_UI, L2tpPluginUi))
#define L2TP_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), L2TP_TYPE_PLUGIN_UI, L2tpPluginUiClass))
#define L2TP_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), L2TP_TYPE_PLUGIN_UI))
#define L2TP_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), L2TP_TYPE_PLUGIN_UI))
#define L2TP_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), L2TP_TYPE_PLUGIN_UI, L2tpPluginUiClass))

typedef struct _L2tpPluginUi L2tpPluginUi;
typedef struct _L2tpPluginUiClass L2tpPluginUiClass;

struct _L2tpPluginUi {
	GObject parent;
};

struct _L2tpPluginUiClass {
	GObjectClass parent;
};

GType l2tp_plugin_ui_get_type (void);


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

#endif	/* _NM_L2TP_H_ */

