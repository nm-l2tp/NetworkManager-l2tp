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
 * (C) Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-secret-utils.h"

/*****************************************************************************/

void
nm_explicit_bzero (void *s, gsize n)
{
	/* gracefully handle n == 0. This is important, callers rely on it. */
	if (n > 0) {
		nm_assert (s);
#if defined (HAVE_DECL_EXPLICIT_BZERO) && HAVE_DECL_EXPLICIT_BZERO
		explicit_bzero (s, n);
#else
		/* don't bother with a workaround. Use a reasonable glibc. */
		memset (s, 0, n);
#endif
	}
}

/*****************************************************************************/

char *
nm_secret_strchomp (char *secret)
{
	gsize len;

	g_return_val_if_fail (secret, NULL);

	/* it's actually identical to g_strchomp(). However,
	 * the glib function does not document, that it clears the
	 * memory. For @secret, we don't only want to truncate trailing
	 * spaces, we want to overwrite them with NUL. */

	len = strlen (secret);
	while (len--) {
		if (g_ascii_isspace ((guchar) secret[len]))
			secret[len] = '\0';
		else
			break;
	}

	return secret;
}

/*****************************************************************************/

GBytes *
nm_secret_copy_to_gbytes (gconstpointer mem, gsize mem_len)
{
	NMSecretBuf *b;

	if (mem_len == 0)
		return g_bytes_new_static ("", 0);

	nm_assert (mem);

	/* NUL terminate the buffer.
	 *
	 * The entire buffer is already malloc'ed and likely has some room for padding.
	 * Thus, in many situations, this additional byte will cause no overhead in
	 * practice.
	 *
	 * Even if it causes an overhead, do it just for safety. Yes, the returned
	 * bytes is not a NUL terminated string and no user must rely on this. Do
	 * not treat binary data as NUL terminated strings, unless you know what
	 * you are doing. Anyway, defensive FTW.
	 */

	b = nm_secret_buf_new (mem_len + 1);
	memcpy (b->bin, mem, mem_len);
	b->bin[mem_len] = 0;
	return nm_secret_buf_to_gbytes_take (b, mem_len);
}

/*****************************************************************************/

NMSecretBuf *
nm_secret_buf_new (gsize len)
{
	NMSecretBuf *secret;

	nm_assert (len > 0);

	secret = g_malloc (sizeof (NMSecretBuf) + len);
	*((gsize *) &(secret->len)) = len;
	return secret;
}

static void
_secret_buf_free (gpointer user_data)
{
	NMSecretBuf *secret = user_data;

	nm_assert (secret);
	nm_assert (secret->len > 0);

	nm_explicit_bzero (secret->bin, secret->len);
	g_free (user_data);
}

GBytes *
nm_secret_buf_to_gbytes_take (NMSecretBuf *secret, gssize actual_len)
{
	nm_assert (secret);
	nm_assert (secret->len > 0);
	nm_assert (actual_len == -1 || (actual_len >= 0 && actual_len <= secret->len));
	return g_bytes_new_with_free_func (secret->bin,
	                                   actual_len >= 0 ? (gsize) actual_len : secret->len,
	                                   _secret_buf_free,
	                                   secret);
}
