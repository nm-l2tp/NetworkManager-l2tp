// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright 2016 Red Hat, Inc.
 */

#ifndef __NM_VPN_PLUGIN_MACROS_H__
#define __NM_VPN_PLUGIN_MACROS_H__

#include <syslog.h>

static inline int
nm_utils_syslog_coerce_from_nm (int syslog_level)
{
	/* NetworkManager uses internally NMLogLevel levels. When spawning
	 * the VPN plugin, it maps those levels to syslog levels as follows:
	 *
	 *  LOGL_INFO = LOG_NOTICE,
	 *  LOGL_DEBUG = LOG_INFO,
	 *  LOGL_TRACE = LOG_DEBUG,
	 *
	 * However, when actually printing to syslog, we don't want to print messages
	 * with LOGL_INFO level as LOG_NOTICE, because they are *not* to be highlighted.
	 *
	 * In other words: NetworkManager has 3 levels that should not require highlighting:
	 * LOGL_INFO, LOGL_DEBUG, LOGL_TRACE. syslog on the other hand has only LOG_INFO and LOG_DEBUG.
	 *
	 * So, coerce those values before printing to syslog. When you receive the syslog_level
	 * from NetworkManager, instead of calling
	 *   syslog(syslog_level, ...)
	 * you should call
	 *   syslog(nm_utils_syslog_coerce_from_nm(syslog_level), ...)
	 */
	switch (syslog_level) {
	case LOG_INFO:
		return LOG_DEBUG;
	case LOG_NOTICE:
		return LOG_INFO;
	default:
		return syslog_level;
	}
}

static inline const char *
nm_utils_syslog_to_str (int syslog_level)
{
	/* Maps the levels the same way as NetworkManager's nm-logging.c does */
	if (syslog_level >= LOG_DEBUG)
		return "<trace>";
	if (syslog_level >= LOG_INFO)
		return "<debug>";
	if (syslog_level >= LOG_NOTICE)
		return "<info>";
	if (syslog_level >= LOG_WARNING)
		return "<warn>";
	return "<error>";
}

/*****************************************************************************/

/* possibly missing defines from newer libnm API. */

#ifndef NM_VPN_PLUGIN_CONFIG_PROXY_PAC
#define NM_VPN_PLUGIN_CONFIG_PROXY_PAC "pac"
#endif

#ifndef NM_VPN_PLUGIN_IP4_CONFIG_PRESERVE_ROUTES
#define NM_VPN_PLUGIN_IP4_CONFIG_PRESERVE_ROUTES "preserve-routes"
#endif

#ifndef NM_VPN_PLUGIN_IP6_CONFIG_PRESERVE_ROUTES
#define NM_VPN_PLUGIN_IP6_CONFIG_PRESERVE_ROUTES "preserve-routes"
#endif

/*****************************************************************************/

#endif /* __NM_VPN_PLUGIN_MACROS_H__ */

