/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * Copyright 2016,2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-vpn-plugin-utils.h"

#include <dlfcn.h>

/*****************************************************************************/

NMVpnEditor *
nm_vpn_plugin_utils_load_editor (const char *module_name,
                                 const char *factory_name,
                                 NMVpnPluginUtilsEditorFactory editor_factory,
                                 NMVpnEditorPlugin *editor_plugin,
                                 NMConnection *connection,
                                 gpointer user_data,
                                 GError **error)

{
	static struct {
		gpointer factory;
		void *dl_module;
		char *module_name;
		char *factory_name;
	} cached = { 0 };
	NMVpnEditor *editor;
	gs_free char *module_path = NULL;
	gs_free char *dirname = NULL;
	Dl_info plugin_info;

	g_return_val_if_fail (module_name, NULL);
	g_return_val_if_fail (factory_name && factory_name[0], NULL);
	g_return_val_if_fail (editor_factory, NULL);
	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (editor_plugin), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	if (!g_path_is_absolute (module_name)) {
		/*
		 * Load an editor from the same directory this plugin is in.
		 * Ideally, we'd get our .so name from the NMVpnEditorPlugin if it
		 * would just have a property with it...
		 */
		if (!dladdr(nm_vpn_plugin_utils_load_editor, &plugin_info)) {
			/* Really a "can not happen" scenario. */
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_FAILED,
			             _("unable to get editor plugin name: %s"), dlerror ());
		}

		dirname = g_path_get_dirname (plugin_info.dli_fname);
		module_path = g_build_filename (dirname, module_name, NULL);
	} else {
		module_path = g_strdup (module_name);
	}

	/* we really expect this function to be called with unchanging @module_name
	 * and @factory_name. And we only want to load the module once, hence it would
	 * be more complicated to accept changing @module_name/@factory_name arguments.
	 *
	 * The reason for only loading once is that due to glib types, we cannot create a
	 * certain type-name more then once, so loading the same module or another version
	 * of the same module will fail horribly as both try to create a GType with the same
	 * name.
	 *
	 * Only support loading once, any future calls will reuse the handle. To simplify
	 * that, we enforce that the @factory_name and @module_name is the same. */
	if (cached.factory) {
		g_return_val_if_fail (cached.dl_module, NULL);
		g_return_val_if_fail (cached.factory_name && nm_streq0 (cached.factory_name, factory_name), NULL);
		g_return_val_if_fail (cached.module_name && nm_streq0 (cached.module_name, module_name), NULL);
	} else {
		gpointer factory;
		void *dl_module;

		dl_module = dlopen (module_path, RTLD_LAZY | RTLD_LOCAL);
		if (!dl_module) {
			if (!g_file_test (module_path, G_FILE_TEST_EXISTS)) {
				g_set_error (error,
				             G_FILE_ERROR,
				             G_FILE_ERROR_NOENT,
				             _("missing plugin file \"%s\""), module_path);
				return NULL;
			}
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_FAILED,
			             _("cannot load editor plugin: %s"), dlerror ());
			return NULL;
		}

		factory = dlsym (dl_module, factory_name);
		if (!factory) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_FAILED,
			             _("cannot load factory %s from plugin: %s"),
			             factory_name, dlerror ());
			dlclose (dl_module);
			return NULL;
		}

		/* we cannot ever unload the module because it creates glib types, which
		 * cannot be unregistered.
		 *
		 * Thus we just leak the dl_module handle indefinitely. */
		cached.factory = factory;
		cached.dl_module = dl_module;
		cached.module_name = g_strdup (module_name);
		cached.factory_name = g_strdup (factory_name);
	}

	editor = editor_factory (cached.factory,
	                         editor_plugin,
	                         connection,
	                         user_data,
	                         error);
	if (!editor) {
		if (error && !*error ) {
			g_set_error_literal (error,
			                     NM_VPN_PLUGIN_ERROR,
			                     NM_VPN_PLUGIN_ERROR_FAILED,
			                     _("unknown error creating editor instance"));
			g_return_val_if_reached (NULL);
		}
		return NULL;
	}

	g_return_val_if_fail (NM_IS_VPN_EDITOR (editor), NULL);
	return editor;
}
