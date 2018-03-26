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
 * (C) Copyright 2016 Red Hat, Inc.
 */

#ifndef __NM_SHARED_UTILS_H__
#define __NM_SHARED_UTILS_H__

#include <netinet/in.h>

/*****************************************************************************/

static inline char
nm_utils_addr_family_to_char (int addr_family)
{
	switch (addr_family) {
	case AF_INET:  return '4';
	case AF_INET6: return '6';
	}
	g_return_val_if_reached ('?');
}

static inline gsize
nm_utils_addr_family_to_size (int addr_family)
{
	switch (addr_family) {
	case AF_INET:  return sizeof (in_addr_t);
	case AF_INET6: return sizeof (struct in6_addr);
	}
	g_return_val_if_reached (0);
}

#define nm_assert_addr_family(addr_family) \
	nm_assert (NM_IN_SET ((addr_family), AF_INET, AF_INET6))

/*****************************************************************************/

typedef struct {
	union {
		guint8 addr_ptr[1];
		in_addr_t addr4;
		struct in6_addr addr6;

		/* NMIPAddr is really a union for IP addresses.
		 * However, as ethernet addresses fit in here nicely, use
		 * it also for an ethernet MAC address. */
		guint8 addr_eth[6 /*ETH_ALEN*/];
	};
} NMIPAddr;

extern const NMIPAddr nm_ip_addr_zero;

static inline void
nm_ip_addr_set (int addr_family, gpointer dst, const NMIPAddr *src)
{
	nm_assert_addr_family (addr_family);
	nm_assert (dst);
	nm_assert (src);

	if (addr_family != AF_INET6)
		*((in_addr_t *) dst) = src->addr4;
	else
		*((struct in6_addr *) dst) = src->addr6;
}

/*****************************************************************************/

#define NM_CMP_RETURN(c) \
    G_STMT_START { \
        const int _cc = (c); \
        if (_cc) \
            return _cc < 0 ? -1 : 1; \
    } G_STMT_END

#define NM_CMP_SELF(a, b) \
    G_STMT_START { \
        typeof (a) _a = (a); \
        typeof (b) _b = (b); \
        \
        if (_a == _b) \
            return 0; \
        if (!_a) \
            return -1; \
        if (!_b) \
            return 1; \
    } G_STMT_END

#define NM_CMP_DIRECT(a, b) \
    G_STMT_START { \
        typeof (a) _a = (a); \
        typeof (b) _b = (b); \
        \
        if (_a != _b) \
            return (_a < _b) ? -1 : 1; \
    } G_STMT_END

#define NM_CMP_DIRECT_MEMCMP(a, b, size) \
    NM_CMP_RETURN (memcmp ((a), (b), (size)))

#define NM_CMP_DIRECT_IN6ADDR(a, b) \
    G_STMT_START { \
        const struct in6_addr *const _a = (a); \
        const struct in6_addr *const _b = (b); \
        NM_CMP_RETURN (memcmp (_a, _b, sizeof (struct in6_addr))); \
    } G_STMT_END

#define NM_CMP_FIELD(a, b, field) \
    NM_CMP_DIRECT (((a)->field), ((b)->field))

#define NM_CMP_FIELD_UNSAFE(a, b, field) \
    G_STMT_START { \
        /* it's unsafe, because it evaluates the arguments more then once.
         * This is necessary for bitfields, for which typeof() doesn't work. */ \
        if (((a)->field) != ((b)->field)) \
            return ((a)->field < ((b)->field)) ? -1 : 1; \
    } G_STMT_END

#define NM_CMP_FIELD_BOOL(a, b, field) \
    NM_CMP_DIRECT (!!((a)->field), !!((b)->field))

#define NM_CMP_FIELD_STR(a, b, field) \
    NM_CMP_RETURN (strcmp (((a)->field), ((b)->field)))

#define NM_CMP_FIELD_STR_INTERNED(a, b, field) \
    G_STMT_START { \
        const char *_a = ((a)->field); \
        const char *_b = ((b)->field); \
        \
        if (_a != _b) { \
            NM_CMP_RETURN (g_strcmp0 (_a, _b)); \
        } \
    } G_STMT_END

#define NM_CMP_FIELD_STR0(a, b, field) \
    NM_CMP_RETURN (g_strcmp0 (((a)->field), ((b)->field)))

#define NM_CMP_FIELD_MEMCMP_LEN(a, b, field, len) \
    NM_CMP_RETURN (memcmp (&((a)->field), &((b)->field), \
                           MIN (len, sizeof ((a)->field))))

#define NM_CMP_FIELD_MEMCMP(a, b, field) \
    NM_CMP_RETURN (memcmp (&((a)->field), \
                           &((b)->field), \
                           sizeof ((a)->field)))

#define NM_CMP_FIELD_IN6ADDR(a, b, field) \
    G_STMT_START { \
        const struct in6_addr *const _a = &((a)->field); \
        const struct in6_addr *const _b = &((b)->field); \
        NM_CMP_RETURN (memcmp (_a, _b, sizeof (struct in6_addr))); \
    } G_STMT_END

/*****************************************************************************/

extern const void *const _NM_PTRARRAY_EMPTY[1];

#define NM_PTRARRAY_EMPTY(type) ((type const*) _NM_PTRARRAY_EMPTY)

static inline void
_nm_utils_strbuf_init (char *buf, gsize len, char **p_buf_ptr, gsize *p_buf_len)
{
	NM_SET_OUT (p_buf_len, len);
	NM_SET_OUT (p_buf_ptr, buf);
	buf[0] = '\0';
}

#define nm_utils_strbuf_init(buf, p_buf_ptr, p_buf_len) \
	G_STMT_START { \
		G_STATIC_ASSERT (G_N_ELEMENTS (buf) == sizeof (buf) && sizeof (buf) > sizeof (char *)); \
		_nm_utils_strbuf_init ((buf), sizeof (buf), (p_buf_ptr), (p_buf_len)); \
	} G_STMT_END
void nm_utils_strbuf_append (char **buf, gsize *len, const char *format, ...) _nm_printf (3, 4);
void nm_utils_strbuf_append_c (char **buf, gsize *len, char c);
void nm_utils_strbuf_append_str (char **buf, gsize *len, const char *str);

const char *nm_strquote (char *buf, gsize buf_len, const char *str);

/*****************************************************************************/

const char **nm_utils_strsplit_set (const char *str, const char *delimiters);

gssize nm_utils_strv_find_first (char **list, gssize len, const char *needle);

char **_nm_utils_strv_cleanup (char **strv,
                               gboolean strip_whitespace,
                               gboolean skip_empty,
                               gboolean skip_repeated);

/*****************************************************************************/

guint32 _nm_utils_ip4_prefix_to_netmask (guint32 prefix);
guint32 _nm_utils_ip4_get_default_prefix (guint32 ip);

gboolean nm_utils_ip_is_site_local (int addr_family,
                                    const void *address);

/*****************************************************************************/

gboolean nm_utils_parse_inaddr_bin  (int addr_family,
                                     const char *text,
                                     gpointer out_addr);

gboolean nm_utils_parse_inaddr (int addr_family,
                                const char *text,
                                char **out_addr);

gboolean nm_utils_parse_inaddr_prefix_bin (int addr_family,
                                           const char *text,
                                           gpointer out_addr,
                                           int *out_prefix);

gboolean nm_utils_parse_inaddr_prefix (int addr_family,
                                       const char *text,
                                       char **out_addr,
                                       int *out_prefix);

gint64 _nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback);

gint _nm_utils_ascii_str_to_bool (const char *str,
                                  gint default_value);

/*****************************************************************************/

extern char _nm_utils_to_string_buffer[2096];

void     nm_utils_to_string_buffer_init (char **buf, gsize *len);
gboolean nm_utils_to_string_buffer_init_null (gconstpointer obj, char **buf, gsize *len);

/*****************************************************************************/

typedef struct {
	unsigned flag;
	const char *name;
} NMUtilsFlags2StrDesc;

#define NM_UTILS_FLAGS2STR(f, n) { .flag = f, .name = ""n, }

#define _NM_UTILS_FLAGS2STR_DEFINE(scope, fcn_name, flags_type, ...) \
scope const char * \
fcn_name (flags_type flags, char *buf, gsize len) \
{ \
	static const NMUtilsFlags2StrDesc descs[] = { \
		__VA_ARGS__ \
	}; \
	G_STATIC_ASSERT (sizeof (flags_type) <= sizeof (unsigned)); \
	return nm_utils_flags2str (descs, G_N_ELEMENTS (descs), flags, buf, len); \
};

#define NM_UTILS_FLAGS2STR_DEFINE(fcn_name, flags_type, ...) \
	_NM_UTILS_FLAGS2STR_DEFINE (, fcn_name, flags_type, __VA_ARGS__)
#define NM_UTILS_FLAGS2STR_DEFINE_STATIC(fcn_name, flags_type, ...) \
	_NM_UTILS_FLAGS2STR_DEFINE (static, fcn_name, flags_type, __VA_ARGS__)

const char *nm_utils_flags2str (const NMUtilsFlags2StrDesc *descs,
                                gsize n_descs,
                                unsigned flags,
                                char *buf,
                                gsize len);

/*****************************************************************************/

#define NM_UTILS_ENUM2STR(v, n)     (void) 0; case v: s = ""n""; break; (void) 0
#define NM_UTILS_ENUM2STR_IGNORE(v) (void) 0; case v: break; (void) 0

#define _NM_UTILS_ENUM2STR_DEFINE(scope, fcn_name, lookup_type, int_fmt, ...) \
scope const char * \
fcn_name (lookup_type val, char *buf, gsize len) \
{ \
	nm_utils_to_string_buffer_init (&buf, &len); \
	if (len) { \
		const char *s = NULL; \
		switch (val) { \
			(void) 0, \
			__VA_ARGS__ \
			(void) 0; \
		}; \
		if (s) \
			g_strlcpy (buf, s, len); \
		else \
			g_snprintf (buf, len, "(%"int_fmt")", val); \
	} \
	return buf; \
}

#define NM_UTILS_ENUM2STR_DEFINE(fcn_name, lookup_type, ...) \
	_NM_UTILS_ENUM2STR_DEFINE (, fcn_name, lookup_type, "d", __VA_ARGS__)
#define NM_UTILS_ENUM2STR_DEFINE_STATIC(fcn_name, lookup_type, ...) \
	_NM_UTILS_ENUM2STR_DEFINE (static, fcn_name, lookup_type, "d", __VA_ARGS__)

/*****************************************************************************/

#define _nm_g_slice_free_fcn_define(mem_size) \
static inline void \
_nm_g_slice_free_fcn_##mem_size (gpointer mem_block) \
{ \
	g_slice_free1 (mem_size, mem_block); \
}

_nm_g_slice_free_fcn_define (1)
_nm_g_slice_free_fcn_define (2)
_nm_g_slice_free_fcn_define (4)
_nm_g_slice_free_fcn_define (8)
_nm_g_slice_free_fcn_define (12)
_nm_g_slice_free_fcn_define (16)

#define _nm_g_slice_free_fcn1(mem_size) \
	({ \
		void (*_fcn) (gpointer); \
		\
		/* If mem_size is a compile time constant, the compiler
		 * will be able to optimize this. Hence, you don't want
		 * to call this with a non-constant size argument. */ \
		switch (mem_size) { \
		case  1: _fcn = _nm_g_slice_free_fcn_1;  break; \
		case  2: _fcn = _nm_g_slice_free_fcn_2;  break; \
		case  4: _fcn = _nm_g_slice_free_fcn_4;  break; \
		case  8: _fcn = _nm_g_slice_free_fcn_8;  break; \
		case 12: _fcn = _nm_g_slice_free_fcn_12;  break; \
		case 16: _fcn = _nm_g_slice_free_fcn_16; break; \
		default: g_assert_not_reached (); _fcn = NULL; break; \
		} \
		_fcn; \
	})

/**
 * nm_g_slice_free_fcn:
 * @type: type argument for sizeof() operator that you would
 *   pass to g_slice_new().
 *
 * Returns: a function pointer with GDestroyNotify signature
 *   for g_slice_free(type,*).
 *
 * Only certain types are implemented. You'll get an assertion
 * using the wrong type. */
#define nm_g_slice_free_fcn(type) (_nm_g_slice_free_fcn1 (sizeof (type)))

#define nm_g_slice_free_fcn_gint64 (nm_g_slice_free_fcn (gint64))

/*****************************************************************************/

/**
 * NMUtilsError:
 * @NM_UTILS_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_UTILS_ERROR_CANCELLED_DISPOSING: when disposing an object that has
 *   pending aynchronous operations, the operation is cancelled with this
 *   error reason. Depending on the usage, this might indicate a bug because
 *   usually the target object should stay alive as long as there are pending
 *   operations.
 * @NM_UTILS_ERROR_INVALID_ARGUMENT: invalid argument.
 */
typedef enum {
	NM_UTILS_ERROR_UNKNOWN = 0,                 /*< nick=Unknown >*/
	NM_UTILS_ERROR_CANCELLED_DISPOSING,         /*< nick=CancelledDisposing >*/
	NM_UTILS_ERROR_INVALID_ARGUMENT,            /*< nick=InvalidArgument >*/
} NMUtilsError;

#define NM_UTILS_ERROR (nm_utils_error_quark ())
GQuark nm_utils_error_quark (void);

void nm_utils_error_set_cancelled (GError **error,
                                   gboolean is_disposing,
                                   const char *instance_name);
gboolean nm_utils_error_is_cancelled (GError *error,
                                      gboolean consider_is_disposing);

/*****************************************************************************/

gboolean nm_g_object_set_property (GObject *object,
                                   const gchar  *property_name,
                                   const GValue *value,
                                   GError **error);

gboolean nm_g_object_set_property_boolean (GObject *object,
                                           const gchar  *property_name,
                                           gboolean value,
                                           GError **error);

gboolean nm_g_object_set_property_uint (GObject *object,
                                        const gchar  *property_name,
                                        guint value,
                                        GError **error);

GParamSpec *nm_g_object_class_find_property_from_gtype (GType gtype,
                                                        const char *property_name);

/*****************************************************************************/

typedef enum {
	NM_UTILS_STR_UTF8_SAFE_FLAG_NONE                = 0,
	NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL         = 0x0001,
	NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII    = 0x0002,
} NMUtilsStrUtf8SafeFlags;

const char *nm_utils_str_utf8safe_escape   (const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free);
const char *nm_utils_str_utf8safe_unescape (const char *str, char **to_free);

char *nm_utils_str_utf8safe_escape_cp   (const char *str, NMUtilsStrUtf8SafeFlags flags);
char *nm_utils_str_utf8safe_unescape_cp (const char *str);

char *nm_utils_str_utf8safe_escape_take (char *str, NMUtilsStrUtf8SafeFlags flags);

/*****************************************************************************/

typedef struct {
	const char *name;
} NMUtilsNamedEntry;

typedef struct {
	union {
		NMUtilsNamedEntry named_entry;
		const char *name;
	};
	union {
		const char *value_str;
		gconstpointer value_ptr;
	};
} NMUtilsNamedValue;

#define nm_utils_named_entry_cmp           nm_strcmp_p
#define nm_utils_named_entry_cmp_with_data nm_strcmp_p_with_data

/*****************************************************************************/

#define NM_UTILS_NS_PER_SECOND  ((gint64) 1000000000)
#define NM_UTILS_NS_PER_MSEC    ((gint64) 1000000)
#define NM_UTILS_NS_TO_MSEC_CEIL(nsec)      (((nsec) + (NM_UTILS_NS_PER_MSEC - 1)) / NM_UTILS_NS_PER_MSEC)

/*****************************************************************************/

int nm_utils_fd_wait_for_event (int fd, int event, gint64 timeout_ns);
ssize_t nm_utils_fd_read_loop (int fd, void *buf, size_t nbytes, bool do_poll);
int nm_utils_fd_read_loop_exact (int fd, void *buf, size_t nbytes, bool do_poll);

/*****************************************************************************/

#endif /* __NM_SHARED_UTILS_H__ */
