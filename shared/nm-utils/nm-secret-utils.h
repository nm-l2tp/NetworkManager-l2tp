// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager -- Network link manager
 *
 * (C) Copyright 2018 Red Hat, Inc.
 */

#ifndef __NM_SECRET_UTILS_H__
#define __NM_SECRET_UTILS_H__

#include "nm-macros-internal.h"

/*****************************************************************************/

void nm_explicit_bzero (void *s, gsize n);

/*****************************************************************************/

char *nm_secret_strchomp (char *secret);

/*****************************************************************************/

static inline void
nm_free_secret (char *secret)
{
	if (secret) {
		nm_explicit_bzero (secret, strlen (secret));
		g_free (secret);
	}
}

NM_AUTO_DEFINE_FCN0 (char *, _nm_auto_free_secret, nm_free_secret)
/**
 * nm_auto_free_secret:
 *
 * Call g_free() on a variable location when it goes out of scope.
 * Also, previously, calls memset(loc, 0, strlen(loc)) to clear out
 * the secret.
 */
#define nm_auto_free_secret nm_auto(_nm_auto_free_secret)

/*****************************************************************************/

GBytes *nm_secret_copy_to_gbytes (gconstpointer mem, gsize mem_len);

/*****************************************************************************/

/* NMSecretPtr is a pair of malloc'ed data pointer and the length of the
 * data. The purpose is to use it in combination with nm_auto_clear_secret_ptr
 * which ensures that the data pointer (with all len bytes) is cleared upon
 * cleanup. */
typedef struct {
	gsize len;

	/* the data pointer. This pointer must be allocated with malloc (at least
	 * when used with nm_secret_ptr_clear()). */
	union {
		char *str;
		void *ptr;
		guint8 *bin;
	};
} NMSecretPtr;

static inline void
nm_secret_ptr_clear (NMSecretPtr *secret)
{
	if (secret) {
		if (secret->len > 0) {
			if (secret->ptr)
				nm_explicit_bzero (secret->ptr, secret->len);
			secret->len = 0;
		}
		nm_clear_g_free (&secret->ptr);
	}
}

#define nm_auto_clear_secret_ptr nm_auto(nm_secret_ptr_clear)

#define NM_SECRET_PTR_STATIC(_len) \
	((const NMSecretPtr) { \
		.len = _len, \
		.ptr = ((guint8 [_len]) { }), \
	})

static inline void
nm_secret_ptr_clear_static (const NMSecretPtr *secret)
{
	if (secret) {
		if (secret->len > 0) {
			nm_assert (secret->ptr);
			nm_explicit_bzero (secret->ptr, secret->len);
		}
	}
}

#define nm_auto_clear_static_secret_ptr nm_auto(nm_secret_ptr_clear_static)

static inline void
nm_secret_ptr_move (NMSecretPtr *dst, NMSecretPtr *src)
{
	if (dst && dst != src) {
		*dst = *src;
		src->len = 0;
		src->ptr = NULL;
	}
}

/*****************************************************************************/

typedef struct {
	const gsize len;
	union {
		char str[0];
		guint8 bin[0];
	};
} NMSecretBuf;

static inline void
_nm_auto_free_secret_buf (NMSecretBuf **ptr)
{
	NMSecretBuf *b = *ptr;

	if (b) {
		nm_assert (b->len > 0);
		nm_explicit_bzero (b->bin, b->len);
		g_free (b);
	}
}
#define nm_auto_free_secret_buf nm_auto(_nm_auto_free_secret_buf)

NMSecretBuf *nm_secret_buf_new (gsize len);

GBytes *nm_secret_buf_to_gbytes_take (NMSecretBuf *secret, gssize actual_len);

/*****************************************************************************/

#endif /* __NM_SECRET_UTILS_H__ */
