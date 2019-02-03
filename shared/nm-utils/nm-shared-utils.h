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

static inline gboolean
_NM_INT_NOT_NEGATIVE (gssize val)
{
	/* whether an enum (without negative values) is a signed int, depends on compiler options
	 * and compiler implementation.
	 *
	 * When using such an enum for accessing an array, one naturally wants to check
	 * that the enum is not negative. However, the compiler doesn't like a plain
	 * comparison "enum_val >= 0", because (if the enum is unsigned), it will warn
	 * that the expression is always true *duh*. Not even a cast to a signed
	 * type helps to avoid the compiler warning in any case.
	 *
	 * The sole purpose of this function is to avoid a compiler warning, when checking
	 * that an enum is not negative. */
	return val >= 0;
}

/* check whether the integer value is smaller than G_MAXINT32. This macro exists
 * for the sole purpose, that a plain "((int) value <= G_MAXINT32)" comparison
 * may cause the compiler or coverity that this check is always TRUE. But the
 * check depends on compile time and the size of C type "int".  Of course, most
 * of the time in is gint32 and an int value is always <= G_MAXINT32.  The check
 * exists to catch cases where that is not true.
 *
 * Together with the G_STATIC_ASSERT(), we make sure that this is always satisfied. */
G_STATIC_ASSERT (sizeof (int) == sizeof (gint32));
#if _NM_CC_SUPPORT_GENERIC
#define _NM_INT_LE_MAXINT32(value) \
	({ \
		_nm_unused typeof (value) _value = (value); \
		\
		_Generic((value), \
		         int: TRUE \
		); \
	})
#else
#define _NM_INT_LE_MAXINT32(value) ({ \
		_nm_unused typeof (value) _value = (value); \
		_nm_unused const int *_p_value = &_value; \
		\
		TRUE; \
	})
#endif

/*****************************************************************************/

static inline char
nm_utils_addr_family_to_char (int addr_family)
{
	switch (addr_family) {
	case AF_UNSPEC: return 'X';
	case AF_INET:   return '4';
	case AF_INET6:  return '6';
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
		struct in_addr addr4_struct;
		struct in6_addr addr6;

		/* NMIPAddr is really a union for IP addresses.
		 * However, as ethernet addresses fit in here nicely, use
		 * it also for an ethernet MAC address. */
		guint8 addr_eth[6 /*ETH_ALEN*/];
	};
} NMIPAddr;

extern const NMIPAddr nm_ip_addr_zero;

static inline void
nm_ip_addr_set (int addr_family, gpointer dst, gconstpointer src)
{
	nm_assert_addr_family (addr_family);
	nm_assert (dst);
	nm_assert (src);

	memcpy (dst,
	        src,
	        (addr_family != AF_INET6)
	          ? sizeof (in_addr_t)
	          : sizeof (struct in6_addr));
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

#define NM_CMP_DIRECT_STRCMP0(a, b) \
    NM_CMP_RETURN (g_strcmp0 ((a), (b)))

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

gboolean nm_utils_memeqzero (gconstpointer data, gsize length);

/*****************************************************************************/

/* like g_memdup(). The difference is that the @size argument is of type
 * gsize, while g_memdup() has type guint. Since, the size of container types
 * like GArray is guint as well, this means trying to g_memdup() an
 * array,
 *    g_memdup (array->data, array->len * sizeof (ElementType))
 * will lead to integer overflow, if there are more than G_MAXUINT/sizeof(ElementType)
 * bytes. That seems unnecessarily dangerous to me.
 * nm_memdup() avoids that, because its size argument is always large enough
 * to contain all data that a GArray can hold.
 *
 * Another minor difference to g_memdup() is that the glib version also
 * returns %NULL if @data is %NULL. E.g. g_memdup(NULL, 1)
 * gives %NULL, but nm_memdup(NULL, 1) crashes. I think that
 * is desirable, because @size MUST be correct at all times. @size
 * may be zero, but one must not claim to have non-zero bytes when
 * passing a %NULL @data pointer.
 */
static inline gpointer
nm_memdup (gconstpointer data, gsize size)
{
	gpointer p;

	if (size == 0)
		return NULL;
	p = g_malloc (size);
	memcpy (p, data, size);
	return p;
}

static inline char *
_nm_strndup_a_step (char *s, const char *str, gsize len)
{
	NM_PRAGMA_WARNING_DISABLE ("-Wstringop-truncation");
	if (len > 0)
		strncpy (s, str, len);
	s[len] = '\0';
	return s;
	NM_PRAGMA_WARNING_REENABLE;
}

/* Similar to g_strndup(), however, if the string (including the terminating
 * NUL char) fits into alloca_maxlen, this will alloca() the memory.
 *
 * It's a mix of strndup() and strndupa(), but deciding based on @alloca_maxlen
 * which one to use.
 *
 * In case malloc() is necessary, @out_str_free will be set (this string
 * must be freed afterwards). It is permissible to pass %NULL as @out_str_free,
 * if you ensure that len < alloca_maxlen.
 *
 * Note that just like g_strndup(), this always returns a buffer with @len + 1
 * bytes, even if strlen(@str) is shorter than that (NUL terminated early). We fill
 * the buffer with strncpy(), which means, that @str is copied up to the first
 * NUL character and then filled with NUL characters. */
#define nm_strndup_a(alloca_maxlen, str, len, out_str_free) \
	({ \
		const gsize _alloca_maxlen = (alloca_maxlen); \
		const char *const _str = (str); \
		const gsize _len = (len); \
		char **const _out_str_free = (out_str_free); \
		char *_s; \
		\
		G_STATIC_ASSERT_EXPR ((alloca_maxlen) <= 300); \
		\
		if (   _out_str_free \
		    && _len >= _alloca_maxlen) { \
			_s = g_malloc (_len + 1); \
			*_out_str_free = _s; \
		} else { \
			g_assert (_len < _alloca_maxlen); \
			_s = g_alloca (_len + 1); \
		} \
		_nm_strndup_a_step (_s, _str, _len); \
	})

/*****************************************************************************/

/* generic macro to convert an int to a (heap allocated) string.
 *
 * Usually, an inline function nm_strdup_int64() would be enough. However,
 * that cannot be used for guint64. So, we would also need nm_strdup_uint64().
 * This causes subtle error potential, because the caller needs to ensure to
 * use the right one (and compiler isn't going to help as it silently casts).
 *
 * Instead, this generic macro is supposed to handle all integers correctly. */
#if _NM_CC_SUPPORT_GENERIC
#define nm_strdup_int(val) \
	_Generic ((val), \
	          char:               g_strdup_printf ("%d",   (int)                (val)), \
	          \
	          signed char:        g_strdup_printf ("%d",   (signed)             (val)), \
	          signed short:       g_strdup_printf ("%d",   (signed)             (val)), \
	          signed:             g_strdup_printf ("%d",   (signed)             (val)), \
	          signed long:        g_strdup_printf ("%ld",  (signed long)        (val)), \
	          signed long long:   g_strdup_printf ("%lld", (signed long long)   (val)), \
	          \
	          unsigned char:      g_strdup_printf ("%u",   (unsigned)           (val)), \
	          unsigned short:     g_strdup_printf ("%u",   (unsigned)           (val)), \
	          unsigned:           g_strdup_printf ("%u",   (unsigned)           (val)), \
	          unsigned long:      g_strdup_printf ("%lu",  (unsigned long)      (val)), \
	          unsigned long long: g_strdup_printf ("%llu", (unsigned long long) (val))  \
	)
#else
#define nm_strdup_int(val) \
	(  (   sizeof (val) == sizeof (guint64) \
	    && ((typeof (val)) -1) > 0) \
	 ? g_strdup_printf ("%"G_GUINT64_FORMAT, (guint64) (val)) \
	 : g_strdup_printf ("%"G_GINT64_FORMAT, (gint64) (val)))
#endif

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
void nm_utils_strbuf_append_bin (char **buf, gsize *len, gconstpointer str, gsize str_len);
void nm_utils_strbuf_seek_end (char **buf, gsize *len);

const char *nm_strquote (char *buf, gsize buf_len, const char *str);

static inline gboolean
nm_utils_is_separator (const char c)
{
	return NM_IN_SET (c, ' ', '\t');
}

/*****************************************************************************/

static inline gboolean
nm_gbytes_equal0 (GBytes *a, GBytes *b)
{
	return a == b || (a && b && g_bytes_equal (a, b));
}

gboolean nm_utils_gbytes_equal_mem (GBytes *bytes,
                                    gconstpointer mem_data,
                                    gsize mem_len);

GVariant *nm_utils_gbytes_to_variant_ay (GBytes *bytes);

/*****************************************************************************/

static inline int
nm_utils_hexchar_to_int (char ch)
{
	G_STATIC_ASSERT_EXPR ('0' < 'A');
	G_STATIC_ASSERT_EXPR ('A' < 'a');

	if (ch >= '0') {
		if (ch <= '9')
			return ch - '0';
		if (ch >= 'A') {
			if (ch <= 'F')
				return ((int) ch) + (10 - (int) 'A');
			if (ch >= 'a' && ch <= 'f')
				return ((int) ch) + (10 - (int) 'a');
		}
	}
	return -1;
}

/*****************************************************************************/

const char *nm_utils_dbus_path_get_last_component (const char *dbus_path);

int nm_utils_dbus_path_cmp (const char *dbus_path_a, const char *dbus_path_b);

/*****************************************************************************/

const char **nm_utils_strsplit_set (const char *str, const char *delimiters, gboolean allow_escaping);

gssize nm_utils_strv_find_first (char **list, gssize len, const char *needle);

char **_nm_utils_strv_cleanup (char **strv,
                               gboolean strip_whitespace,
                               gboolean skip_empty,
                               gboolean skip_repeated);

/*****************************************************************************/

#define NM_UTILS_CHECKSUM_LENGTH_MD5          16
#define NM_UTILS_CHECKSUM_LENGTH_SHA1         20
#define NM_UTILS_CHECKSUM_LENGTH_SHA256       32

#define nm_utils_checksum_get_digest(sum, arr) \
	G_STMT_START { \
		GChecksum *const _sum = (sum); \
		gsize _len; \
		\
		G_STATIC_ASSERT_EXPR (   sizeof (arr) == NM_UTILS_CHECKSUM_LENGTH_MD5 \
		                      || sizeof (arr) == NM_UTILS_CHECKSUM_LENGTH_SHA1 \
		                      || sizeof (arr) == NM_UTILS_CHECKSUM_LENGTH_SHA256); \
		G_STATIC_ASSERT_EXPR (sizeof (arr) == G_N_ELEMENTS (arr)); \
		\
		nm_assert (_sum); \
		\
		_len = G_N_ELEMENTS (arr); \
		\
		g_checksum_get_digest (_sum, (arr), &_len); \
		nm_assert (_len == G_N_ELEMENTS (arr)); \
	} G_STMT_END

#define nm_utils_checksum_get_digest_len(sum, buf, len) \
	G_STMT_START { \
		GChecksum *const _sum = (sum); \
		const gsize _len0 = (len); \
		gsize _len; \
		\
		nm_assert (NM_IN_SET (_len0, NM_UTILS_CHECKSUM_LENGTH_MD5, \
		                             NM_UTILS_CHECKSUM_LENGTH_SHA1, \
		                             NM_UTILS_CHECKSUM_LENGTH_SHA256)); \
		nm_assert (_sum); \
		\
		_len = _len0; \
		g_checksum_get_digest (_sum, (buf), &_len); \
		nm_assert (_len == _len0); \
	} G_STMT_END

/*****************************************************************************/

guint32 _nm_utils_ip4_prefix_to_netmask (guint32 prefix);
guint32 _nm_utils_ip4_get_default_prefix (guint32 ip);

gboolean nm_utils_ip_is_site_local (int addr_family,
                                    const void *address);

/*****************************************************************************/

gboolean nm_utils_parse_inaddr_bin  (int addr_family,
                                     const char *text,
                                     int *out_addr_family,
                                     gpointer out_addr);

gboolean nm_utils_parse_inaddr (int addr_family,
                                const char *text,
                                char **out_addr);

gboolean nm_utils_parse_inaddr_prefix_bin (int addr_family,
                                           const char *text,
                                           int *out_addr_family,
                                           gpointer out_addr,
                                           int *out_prefix);

gboolean nm_utils_parse_inaddr_prefix (int addr_family,
                                       const char *text,
                                       char **out_addr,
                                       int *out_prefix);

gint64  _nm_utils_ascii_str_to_int64  (const char *str, guint base, gint64  min, gint64  max, gint64  fallback);
guint64 _nm_utils_ascii_str_to_uint64 (const char *str, guint base, guint64 min, guint64 max, guint64 fallback);

int _nm_utils_ascii_str_to_bool (const char *str,
                                  int default_value);

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
_nm_g_slice_free_fcn_define (10)
_nm_g_slice_free_fcn_define (12)
_nm_g_slice_free_fcn_define (16)

#define _nm_g_slice_free_fcn1(mem_size) \
	({ \
		void (*_fcn) (gpointer); \
		\
		/* If mem_size is a compile time constant, the compiler
		 * will be able to optimize this. Hence, you don't want
		 * to call this with a non-constant size argument. */ \
		G_STATIC_ASSERT_EXPR (   ((mem_size) ==  1) \
		                      || ((mem_size) ==  2) \
		                      || ((mem_size) ==  4) \
		                      || ((mem_size) ==  8) \
		                      || ((mem_size) == 10) \
		                      || ((mem_size) == 12) \
		                      || ((mem_size) == 16)); \
		switch ((mem_size)) { \
		case  1: _fcn = _nm_g_slice_free_fcn_1;  break; \
		case  2: _fcn = _nm_g_slice_free_fcn_2;  break; \
		case  4: _fcn = _nm_g_slice_free_fcn_4;  break; \
		case  8: _fcn = _nm_g_slice_free_fcn_8;  break; \
		case 10: _fcn = _nm_g_slice_free_fcn_10; break; \
		case 12: _fcn = _nm_g_slice_free_fcn_12; break; \
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
 *
 * @NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE: used for a very particular
 *   purpose during nm_device_check_connection_compatible() to indicate that
 *   the profile does not match the device already because their type differs.
 *   That is, there is a fundamental reason of trying to check a profile that
 *   cannot possibly match on this device.
 * @NM_UTILS_ERROR_CONNECTION_AVAILABLE_UNMANAGED_DEVICE: used for a very particular
 *   purpose during nm_device_check_connection_available(), to indicate that the
 *   device is not available because it is unmanaged.
 * @NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY: the profile is currently not
 *   available/compatible with the device, but this may be only temporary.
 *
 * @NM_UTILS_ERROR_INVALID_ARGUMENT: invalid argument.
 */
typedef enum {
	NM_UTILS_ERROR_UNKNOWN = 0,                 /*< nick=Unknown >*/
	NM_UTILS_ERROR_CANCELLED_DISPOSING,         /*< nick=CancelledDisposing >*/
	NM_UTILS_ERROR_INVALID_ARGUMENT,            /*< nick=InvalidArgument >*/

	/* the following codes have a special meaning and are exactly used for
	 * nm_device_check_connection_compatible() and nm_device_check_connection_available().
	 *
	 * Actually, their meaning is not very important (so, don't think too
	 * hard about the name of these error codes). What is important, is their
	 * relative order (i.e. the integer value of the codes). When manager
	 * searches for a suitable device, it will check all devices whether
	 * a profile can be activated. If they all fail, it will pick the error
	 * message from the device that returned the *highest* error code,
	 * in the hope that this message makes the most sense for the caller.
	 * */
	NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
	NM_UTILS_ERROR_CONNECTION_AVAILABLE_UNMANAGED_DEVICE,
	NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,

} NMUtilsError;

#define NM_UTILS_ERROR (nm_utils_error_quark ())
GQuark nm_utils_error_quark (void);

void nm_utils_error_set_cancelled (GError **error,
                                   gboolean is_disposing,
                                   const char *instance_name);
gboolean nm_utils_error_is_cancelled (GError *error,
                                      gboolean consider_is_disposing);

gboolean nm_utils_error_is_notfound (GError *error);

static inline void
nm_utils_error_set_literal (GError **error, int error_code, const char *literal)
{
	g_set_error_literal (error, NM_UTILS_ERROR, error_code, literal);
}

#define nm_utils_error_set(error, error_code, ...) \
	g_set_error ((error), NM_UTILS_ERROR, error_code, __VA_ARGS__)

#define nm_utils_error_set_errno(error, errsv, fmt, ...) \
	g_set_error ((error), \
	             NM_UTILS_ERROR, \
	             NM_UTILS_ERROR_UNKNOWN, \
	             fmt, \
	             ##__VA_ARGS__, \
	             g_strerror (({ \
	                            const int _errsv = (errsv); \
	                            \
	                            (  _errsv >= 0 \
	                             ? _errsv \
	                             : (  (_errsv == G_MININT) \
	                                ? G_MAXINT \
	                                : -errsv)); \
	                          })))

/*****************************************************************************/

gboolean nm_g_object_set_property (GObject *object,
                                   const char *property_name,
                                   const GValue *value,
                                   GError **error);

gboolean nm_g_object_set_property_string (GObject *object,
                                          const char *property_name,
                                          const char *value,
                                          GError **error);

gboolean nm_g_object_set_property_string_static (GObject *object,
                                                 const char *property_name,
                                                 const char *value,
                                                 GError **error);

gboolean nm_g_object_set_property_string_take (GObject *object,
                                               const char *property_name,
                                               char *value,
                                               GError **error);

gboolean nm_g_object_set_property_boolean (GObject *object,
                                           const char *property_name,
                                           gboolean value,
                                           GError **error);

gboolean nm_g_object_set_property_char (GObject *object,
                                        const char *property_name,
                                        gint8 value,
                                        GError **error);

gboolean nm_g_object_set_property_uchar (GObject *object,
                                         const char *property_name,
                                         guint8 value,
                                         GError **error);

gboolean nm_g_object_set_property_int (GObject *object,
                                       const char *property_name,
                                       int value,
                                       GError **error);

gboolean nm_g_object_set_property_int64 (GObject *object,
                                         const char *property_name,
                                         gint64 value,
                                         GError **error);

gboolean nm_g_object_set_property_uint (GObject *object,
                                        const char *property_name,
                                        guint value,
                                        GError **error);

gboolean nm_g_object_set_property_uint64 (GObject *object,
                                          const char *property_name,
                                          guint64 value,
                                          GError **error);

gboolean nm_g_object_set_property_flags (GObject *object,
                                         const char *property_name,
                                         GType gtype,
                                         guint value,
                                         GError **error);

gboolean nm_g_object_set_property_enum (GObject *object,
                                        const char *property_name,
                                        GType gtype,
                                        int value,
                                        GError **error);

GParamSpec *nm_g_object_class_find_property_from_gtype (GType gtype,
                                                        const char *property_name);

/*****************************************************************************/

typedef enum {
	NM_UTILS_STR_UTF8_SAFE_FLAG_NONE                = 0,
	NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL         = 0x0001,
	NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII    = 0x0002,
} NMUtilsStrUtf8SafeFlags;

const char *nm_utils_buf_utf8safe_escape (gconstpointer buf, gssize buflen, NMUtilsStrUtf8SafeFlags flags, char **to_free);
const char *nm_utils_buf_utf8safe_escape_bytes (GBytes *bytes, NMUtilsStrUtf8SafeFlags flags, char **to_free);
gconstpointer nm_utils_buf_utf8safe_unescape (const char *str, gsize *out_len, gpointer *to_free);

const char *nm_utils_str_utf8safe_escape   (const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free);
const char *nm_utils_str_utf8safe_unescape (const char *str, char **to_free);

char *nm_utils_str_utf8safe_escape_cp   (const char *str, NMUtilsStrUtf8SafeFlags flags);
char *nm_utils_str_utf8safe_unescape_cp (const char *str);

char *nm_utils_str_utf8safe_escape_take (char *str, NMUtilsStrUtf8SafeFlags flags);

static inline void
nm_g_variant_unref_floating (GVariant *var)
{
	/* often a function wants to keep a reference to an input variant.
	 * It uses g_variant_ref_sink() to either increase the ref-count,
	 * or take ownership of a possibly floating reference.
	 *
	 * If the function doesn't actually want to do anything with the
	 * input variant, it still must make sure that a passed in floating
	 * reference is consumed. Hence, this helper which:
	 *
	 *   - does nothing if @var is not floating
	 *   - unrefs (consumes) @var if it is floating. */
	if (g_variant_is_floating (var))
		g_variant_unref (var);
}

/*****************************************************************************/

static inline int
nm_utf8_collate0 (const char *a, const char *b)
{
	if (!a)
		return !b ? 0 : -1;
	if (!b)
		return 1;
	return g_utf8_collate (a, b);
}

int nm_strcmp_p_with_data (gconstpointer a, gconstpointer b, gpointer user_data);
int nm_cmp_uint32_p_with_data (gconstpointer p_a, gconstpointer p_b, gpointer user_data);
int nm_cmp_int2ptr_p_with_data (gconstpointer p_a, gconstpointer p_b, gpointer user_data);

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

NMUtilsNamedValue *nm_utils_named_values_from_str_dict (GHashTable *hash, guint *out_len);

gpointer *nm_utils_hash_keys_to_array (GHashTable *hash,
                                       GCompareDataFunc compare_func,
                                       gpointer user_data,
                                       guint *out_len);

static inline const char **
nm_utils_strdict_get_keys (const GHashTable *hash,
                           gboolean sorted,
                           guint *out_length)
{
	return (const char **) nm_utils_hash_keys_to_array ((GHashTable *) hash,
	                                                    sorted ? nm_strcmp_p_with_data : NULL,
	                                                    NULL,
	                                                    out_length);
}

char **nm_utils_strv_make_deep_copied (const char **strv);

static inline char **
nm_utils_strv_make_deep_copied_nonnull (const char **strv)
{
	return nm_utils_strv_make_deep_copied (strv) ?: g_new0 (char *, 1);
}

/*****************************************************************************/

gssize nm_utils_ptrarray_find_binary_search (gconstpointer *list,
                                             gsize len,
                                             gconstpointer needle,
                                             GCompareDataFunc cmpfcn,
                                             gpointer user_data,
                                             gssize *out_idx_first,
                                             gssize *out_idx_last);

gssize nm_utils_array_find_binary_search (gconstpointer list,
                                          gsize elem_size,
                                          gsize len,
                                          gconstpointer needle,
                                          GCompareDataFunc cmpfcn,
                                          gpointer user_data);

/*****************************************************************************/

typedef gboolean (*NMUtilsHashTableEqualFunc) (gconstpointer a,
                                               gconstpointer b);

gboolean nm_utils_hash_table_equal (const GHashTable *a,
                                    const GHashTable *b,
                                    gboolean treat_null_as_empty,
                                    NMUtilsHashTableEqualFunc equal_func);

/*****************************************************************************/

void _nm_utils_strv_sort (const char **strv, gssize len);
#define nm_utils_strv_sort(strv, len) _nm_utils_strv_sort (NM_CAST_STRV_MC (strv), len)

/*****************************************************************************/

#define NM_UTILS_NS_PER_SECOND   ((gint64) 1000000000)
#define NM_UTILS_NS_PER_MSEC     ((gint64) 1000000)
#define NM_UTILS_MSEC_PER_SECOND ((gint64) 1000)
#define NM_UTILS_NS_TO_MSEC_CEIL(nsec)      (((nsec) + (NM_UTILS_NS_PER_MSEC - 1)) / NM_UTILS_NS_PER_MSEC)

/*****************************************************************************/

int nm_utils_fd_wait_for_event (int fd, int event, gint64 timeout_ns);
ssize_t nm_utils_fd_read_loop (int fd, void *buf, size_t nbytes, bool do_poll);
int nm_utils_fd_read_loop_exact (int fd, void *buf, size_t nbytes, bool do_poll);

/*****************************************************************************/

static inline const char *
nm_utils_dbus_normalize_object_path (const char *path)
{
	/* D-Bus does not allow an empty object path. Hence, whenever we mean NULL / no-object
	 * on D-Bus, it's path is actually "/".
	 *
	 * Normalize that away, and return %NULL in that case. */
	if (path && path[0] == '/' && path[1] == '\0')
		return NULL;
	return path;
}

#define NM_DEFINE_GDBUS_ARG_INFO_FULL(name_, ...) \
	((GDBusArgInfo *) (&((const GDBusArgInfo) { \
		.ref_count = -1, \
		.name = name_, \
		__VA_ARGS__ \
	})))

#define NM_DEFINE_GDBUS_ARG_INFO(name_, a_signature) \
	NM_DEFINE_GDBUS_ARG_INFO_FULL ( \
		name_, \
		.signature = a_signature, \
	)

#define NM_DEFINE_GDBUS_ARG_INFOS(...) \
	((GDBusArgInfo **) ((const GDBusArgInfo *[]) { \
		__VA_ARGS__ \
		NULL, \
	}))

#define NM_DEFINE_GDBUS_PROPERTY_INFO(name_, ...) \
	((GDBusPropertyInfo *) (&((const GDBusPropertyInfo) { \
		.ref_count = -1, \
		.name = name_, \
		__VA_ARGS__ \
	})))

#define NM_DEFINE_GDBUS_PROPERTY_INFO_READABLE(name_, m_signature) \
	NM_DEFINE_GDBUS_PROPERTY_INFO ( \
		name_, \
		.signature = m_signature, \
		.flags = G_DBUS_PROPERTY_INFO_FLAGS_READABLE, \
	)

#define NM_DEFINE_GDBUS_PROPERTY_INFOS(...) \
	((GDBusPropertyInfo **) ((const GDBusPropertyInfo *[]) { \
		__VA_ARGS__ \
		NULL, \
	}))

#define NM_DEFINE_GDBUS_SIGNAL_INFO_INIT(name_, ...) \
	{ \
		.ref_count = -1, \
		.name = name_, \
		__VA_ARGS__ \
	}

#define NM_DEFINE_GDBUS_SIGNAL_INFO(name_, ...) \
	((GDBusSignalInfo *) (&((const GDBusSignalInfo) NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (name_, __VA_ARGS__))))

#define NM_DEFINE_GDBUS_SIGNAL_INFOS(...) \
	((GDBusSignalInfo **) ((const GDBusSignalInfo *[]) { \
		__VA_ARGS__ \
		NULL, \
	}))

#define NM_DEFINE_GDBUS_METHOD_INFO_INIT(name_, ...) \
	{ \
		.ref_count = -1, \
		.name = name_, \
		__VA_ARGS__ \
	}

#define NM_DEFINE_GDBUS_METHOD_INFO(name_, ...) \
	((GDBusMethodInfo *) (&((const GDBusMethodInfo) NM_DEFINE_GDBUS_METHOD_INFO_INIT (name_, __VA_ARGS__))))

#define NM_DEFINE_GDBUS_METHOD_INFOS(...) \
	((GDBusMethodInfo **) ((const GDBusMethodInfo *[]) { \
		__VA_ARGS__ \
		NULL, \
	}))

#define NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(name_, ...) \
	{ \
		.ref_count = -1, \
		.name = name_, \
		__VA_ARGS__ \
	}

#define NM_DEFINE_GDBUS_INTERFACE_INFO(name_, ...) \
	((GDBusInterfaceInfo *) (&((const GDBusInterfaceInfo) NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (name_, __VA_ARGS__))))

#define NM_DEFINE_GDBUS_INTERFACE_VTABLE(...) \
	((GDBusInterfaceVTable *) (&((const GDBusInterfaceVTable) { \
		__VA_ARGS__ \
	})))

/*****************************************************************************/

guint64 nm_utils_get_start_time_for_pid (pid_t pid, char *out_state, pid_t *out_ppid);

/*****************************************************************************/

gpointer _nm_utils_user_data_pack (int nargs, gconstpointer *args);

#define nm_utils_user_data_pack(...) \
	_nm_utils_user_data_pack(NM_NARG (__VA_ARGS__), (gconstpointer[]) { __VA_ARGS__ })

void _nm_utils_user_data_unpack (gpointer user_data, int nargs, ...);

#define nm_utils_user_data_unpack(user_data, ...) \
	_nm_utils_user_data_unpack(user_data, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/*****************************************************************************/

const char *_nm_utils_escape_spaces (const char *str, char **to_free);
char *_nm_utils_unescape_spaces (char *str);

/*****************************************************************************/

typedef void (*NMUtilsInvokeOnIdleCallback) (gpointer callback_user_data,
                                             GCancellable *cancellable);

void nm_utils_invoke_on_idle (NMUtilsInvokeOnIdleCallback callback,
                              gpointer callback_user_data,
                              GCancellable *cancellable);

/*****************************************************************************/

static inline void
nm_strv_ptrarray_add_string_take (GPtrArray *cmd,
                                  char *str)
{
	nm_assert (cmd);
	nm_assert (str);

	g_ptr_array_add (cmd, str);
}

static inline void
nm_strv_ptrarray_add_string_dup (GPtrArray *cmd,
                                 const char *str)
{
	nm_strv_ptrarray_add_string_take (cmd,
	                                  g_strdup (str));
}

#define nm_strv_ptrarray_add_string_concat(cmd, ...) \
	nm_strv_ptrarray_add_string_take ((cmd), g_strconcat (__VA_ARGS__, NULL))

#define nm_strv_ptrarray_add_string_printf(cmd, ...) \
	nm_strv_ptrarray_add_string_take ((cmd), g_strdup_printf (__VA_ARGS__))

#define nm_strv_ptrarray_add_int(cmd, val) \
	nm_strv_ptrarray_add_string_take ((cmd), nm_strdup_int (val))

static inline void
nm_strv_ptrarray_take_gstring (GPtrArray *cmd,
                               GString **gstr)
{
	nm_assert (gstr && *gstr);

	nm_strv_ptrarray_add_string_take (cmd,
	                                  g_string_free (g_steal_pointer (gstr),
	                                                 FALSE));
}

/*****************************************************************************/

int nm_utils_getpagesize (void);

#endif /* __NM_SHARED_UTILS_H__ */
