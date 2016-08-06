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
 * (C) Copyright 2015 Red Hat, Inc.
 */

#ifndef __NM_DEFAULT_H__
#define __NM_DEFAULT_H__

/* makefiles define NETWORKMANAGER_COMPILATION for compiling NetworkManager.
 * Depending on which parts are compiled, different values are set. */
#define NM_NETWORKMANAGER_COMPILATION_DEFAULT             0x0001
#define NM_NETWORKMANAGER_COMPILATION_LIB_BASE            0x0002
#define NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR          0x0004
#define NM_NETWORKMANAGER_COMPILATION_LIB                 (0x0002 | 0x0004)

#ifndef NETWORKMANAGER_COMPILATION
/* For convenience, we don't require our Makefile.am to define
 * -DNETWORKMANAGER_COMPILATION. As we now include this internal header,
 *  we know we do a NETWORKMANAGER_COMPILATION. */
#define NETWORKMANAGER_COMPILATION NM_NETWORKMANAGER_COMPILATION_DEFAULT
#endif

/*****************************************************************************/

#include <config.h>

/* always include these headers for our internal source files. */

#include "nm-utils/nm-glib.h"
#include "nm-utils/gsystem-local-alloc.h"
#include "nm-utils/nm-macros-internal.h"

#include "nm-version.h"
#include "nm-service-defines.h"

/*****************************************************************************/

#if ((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_LIB)

#include <glib/gi18n-lib.h>

#else

#include <glib/gi18n.h>

#endif /* NM_NETWORKMANAGER_COMPILATION_LIB */

/*****************************************************************************/

#ifdef NM_VPN_OLD

#define NM_VPN_LIBNM_COMPAT
#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-8021x.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-vpn.h>
#include <nm-utils.h>
#include <nm-vpn-plugin-ui-interface.h>

#define NMV_EDITOR_PLUGIN_ERROR                     NM_SETTING_VPN_ERROR
#define NMV_EDITOR_PLUGIN_ERROR_FAILED              NM_SETTING_VPN_ERROR_UNKNOWN
#define NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY    NM_SETTING_VPN_ERROR_INVALID_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN        NM_SETTING_VPN_ERROR_UNKNOWN
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_READABLE   NM_SETTING_VPN_ERROR_UNKNOWN

#else /* !NM_VPN_OLD */

#include <NetworkManager.h>

#define NMV_EDITOR_PLUGIN_ERROR                     NM_CONNECTION_ERROR
#define NMV_EDITOR_PLUGIN_ERROR_FAILED              NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY    NM_CONNECTION_ERROR_INVALID_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN        NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_READABLE   NM_CONNECTION_ERROR_FAILED

#endif /* NM_VPN_OLD */

/*****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR

#ifdef NM_VPN_OLD
#include <nm-ui-utils.h>
#else /* NM_VPN_OLD */
#include <nma-ui-utils.h>
#endif /* NM_VPN_OLD */

#endif /* NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR */

/*****************************************************************************/

#endif /* __NM_DEFAULT_H__ */
