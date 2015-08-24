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

#define L2TP_TYPE_EDITOR_PLUGIN            (l2tp_editor_plugin_get_type ())
#define L2TP_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), L2TP_TYPE_EDITOR_PLUGIN, L2tpEditorPlugin))
#define L2TP_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), L2TP_TYPE_EDITOR_PLUGIN, L2tpEditorPluginClass))
#define L2TP_IS_EDITOR_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), L2TP_TYPE_EDITOR_PLUGIN))
#define L2TP_IS_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), L2TP_TYPE_EDITOR_PLUGIN))
#define L2TP_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), L2TP_TYPE_EDITOR_PLUGIN, L2tpEditorPluginClass))

typedef struct _L2tpEditorPlugin L2tpEditorPlugin;
typedef struct _L2tpEditorPluginClass L2tpEditorPluginClass;

struct _L2tpEditorPlugin {
	GObject parent;
};

struct _L2tpEditorPluginClass {
	GObjectClass parent;
};

GType l2tp_editor_plugin_get_type (void);


#define L2TP_TYPE_EDITOR            (l2tp_editor_get_type ())
#define L2TP_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), L2TP_TYPE_EDITOR, L2tpEditor))
#define L2TP_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), L2TP_TYPE_EDITOR, L2tpEditorClass))
#define L2TP_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), L2TP_TYPE_EDITOR))
#define L2TP_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), L2TP_TYPE_EDITOR))
#define L2TP_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), L2TP_TYPE_EDITOR, L2tpEditorClass))

typedef struct _L2tpEditor L2tpEditor;
typedef struct _L2tpEditorClass L2tpEditorClass;

struct _L2tpEditor {
	GObject parent;
};

struct _L2tpEditorClass {
	GObjectClass parent;
};

GType l2tp_editor_get_type (void);

#endif	/* _NM_L2TP_H_ */

