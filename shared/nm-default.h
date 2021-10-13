/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* NetworkManager -- Network link manager
 *
 * (C) Copyright 2015 Red Hat, Inc.
 */

#ifndef __NM_DEFAULT_H__
#define __NM_DEFAULT_H__

/* makefiles define NETWORKMANAGER_COMPILATION for compiling NetworkManager.
 * Depending on which parts are compiled, different values are set. */
#define NM_NETWORKMANAGER_COMPILATION_DEFAULT    0x0001
#define NM_NETWORKMANAGER_COMPILATION_LIB_BASE   0x0002
#define NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR 0x0004
#define NM_NETWORKMANAGER_COMPILATION_LIB        (0x0002 | 0x0004)

/*****************************************************************************/

#ifndef ___CONFIG_H__
#define ___CONFIG_H__
#include <config.h>
#endif

/* always include these headers for our internal source files. */

#include "nm-utils/nm-macros-internal.h"

#include "nm-version.h"
#include "nm-service-defines.h"

/*****************************************************************************/

#if ((NETWORKMANAGER_COMPILATION) &NM_NETWORKMANAGER_COMPILATION_LIB)

#include <glib/gi18n-lib.h>

#else

#include <glib/gi18n.h>

#endif /* NM_NETWORKMANAGER_COMPILATION_LIB */

/*****************************************************************************/

#include <NetworkManager.h>

#define NMV_EDITOR_PLUGIN_ERROR                   NM_CONNECTION_ERROR
#define NMV_EDITOR_PLUGIN_ERROR_FAILED            NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY  NM_CONNECTION_ERROR_INVALID_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_MISSING_PROPERTY  NM_CONNECTION_ERROR_MISSING_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN      NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_READABLE NM_CONNECTION_ERROR_FAILED

/*****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR

#include <nma-ui-utils.h>

#endif /* NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR */

/*****************************************************************************/

#endif /* __NM_DEFAULT_H__ */
