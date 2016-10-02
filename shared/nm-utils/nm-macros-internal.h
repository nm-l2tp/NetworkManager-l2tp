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
 * (C) Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_MACROS_INTERNAL_H__
#define __NM_MACROS_INTERNAL_H__

#include <stdlib.h>

#include "nm-glib.h"

/********************************************************/

#define _nm_packed __attribute__ ((packed))
#define _nm_unused __attribute__ ((unused))
#define _nm_pure   __attribute__ ((pure))
#define _nm_const  __attribute__ ((const))
#define _nm_printf(a,b) __attribute__ ((__format__ (__printf__, a, b)))

#define nm_auto(fcn) __attribute__ ((cleanup(fcn)))

/**
 * nm_auto_free:
 *
 * Call free() on a variable location when it goes out of scope.
 */
#define nm_auto_free nm_auto(_nm_auto_free_impl)
GS_DEFINE_CLEANUP_FUNCTION(void*, _nm_auto_free_impl, free)

static inline void
_nm_auto_unset_gvalue_impl (GValue *v)
{
	g_value_unset (v);
}
#define nm_auto_unset_gvalue nm_auto(_nm_auto_unset_gvalue_impl)

static inline void
_nm_auto_free_gstring_impl (GString **str)
{
	if (*str)
		g_string_free (*str, TRUE);
}
#define nm_auto_free_gstring nm_auto(_nm_auto_free_gstring_impl)

/********************************************************/

/* http://stackoverflow.com/a/11172679 */
#define  _NM_UTILS_MACRO_FIRST(...)                           __NM_UTILS_MACRO_FIRST_HELPER(__VA_ARGS__, throwaway)
#define __NM_UTILS_MACRO_FIRST_HELPER(first, ...)             first

#define  _NM_UTILS_MACRO_REST(...)                            __NM_UTILS_MACRO_REST_HELPER(__NM_UTILS_MACRO_REST_NUM(__VA_ARGS__), __VA_ARGS__)
#define __NM_UTILS_MACRO_REST_HELPER(qty, ...)                __NM_UTILS_MACRO_REST_HELPER2(qty, __VA_ARGS__)
#define __NM_UTILS_MACRO_REST_HELPER2(qty, ...)               __NM_UTILS_MACRO_REST_HELPER_##qty(__VA_ARGS__)
#define __NM_UTILS_MACRO_REST_HELPER_ONE(first)
#define __NM_UTILS_MACRO_REST_HELPER_TWOORMORE(first, ...)    , __VA_ARGS__
#define __NM_UTILS_MACRO_REST_NUM(...) \
    __NM_UTILS_MACRO_REST_SELECT_20TH(__VA_ARGS__, \
                TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE,\
                TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE,\
                TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE, TWOORMORE,\
                TWOORMORE, TWOORMORE, TWOORMORE, ONE, throwaway)
#define __NM_UTILS_MACRO_REST_SELECT_20TH(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, ...) a20

/********************************************************/

/* http://stackoverflow.com/a/2124385/354393 */

#define NM_NARG(...) \
         _NM_NARG(__VA_ARGS__,_NM_NARG_RSEQ_N())
#define _NM_NARG(...) \
         _NM_NARG_ARG_N(__VA_ARGS__)
#define _NM_NARG_ARG_N( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
         _61,_62,_63,N,...) N
#define _NM_NARG_RSEQ_N() \
         63,62,61,60,                   \
         59,58,57,56,55,54,53,52,51,50, \
         49,48,47,46,45,44,43,42,41,40, \
         39,38,37,36,35,34,33,32,31,30, \
         29,28,27,26,25,24,23,22,21,20, \
         19,18,17,16,15,14,13,12,11,10, \
         9,8,7,6,5,4,3,2,1,0

/********************************************************/

#if defined (__GNUC__)
#define _NM_PRAGMA_WARNING_DO(warning)       G_STRINGIFY(GCC diagnostic ignored warning)
#elif defined (__clang__)
#define _NM_PRAGMA_WARNING_DO(warning)       G_STRINGIFY(clang diagnostic ignored warning)
#endif

/* you can only suppress a specific warning that the compiler
 * understands. Otherwise you will get another compiler warning
 * about invalid pragma option.
 * It's not that bad however, because gcc and clang often have the
 * same name for the same warning. */

#if defined (__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#define NM_PRAGMA_WARNING_DISABLE(warning) \
        _Pragma("GCC diagnostic push") \
        _Pragma(_NM_PRAGMA_WARNING_DO(warning))
#elif defined (__clang__)
#define NM_PRAGMA_WARNING_DISABLE(warning) \
        _Pragma("clang diagnostic push") \
        _Pragma(_NM_PRAGMA_WARNING_DO(warning))
#else
#define NM_PRAGMA_WARNING_DISABLE(warning)
#endif

#if defined (__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#define NM_PRAGMA_WARNING_REENABLE \
    _Pragma("GCC diagnostic pop")
#elif defined (__clang__)
#define NM_PRAGMA_WARNING_REENABLE \
    _Pragma("clang diagnostic pop")
#else
#define NM_PRAGMA_WARNING_REENABLE
#endif

/********************************************************/

/**
 * NM_G_ERROR_MSG:
 * @error: (allow none): the #GError instance
 *
 * All functions must follow the convention that when they
 * return a failure, they must also set the GError to a valid
 * message. For external API however, we want to be extra
 * careful before accessing the error instance. Use NM_G_ERROR_MSG()
 * which is safe to use on NULL.
 *
 * Returns: the error message.
 **/
static inline const char *
NM_G_ERROR_MSG (GError *error)
{
	return error ? (error->message ? : "(null)") : "(no-error)"; \
}

/********************************************************/

/* macro to return strlen() of a compile time string. */
#define NM_STRLEN(str)     ( sizeof ("" str) - 1 )

#define NM_SET_OUT(out_val, value) \
	G_STMT_START { \
		typeof(*(out_val)) *_out_val = (out_val); \
		\
		if (_out_val) { \
			*_out_val = (value); \
		} \
	} G_STMT_END

/********************************************************/

#define _NM_IN_SET_EVAL_1(op, _x, y1)                               \
    (_x == (y1))

#define _NM_IN_SET_EVAL_2(op, _x, y1, y2)                           \
    (   (_x == (y1))                                                \
     op (_x == (y2))                                                \
    )

#define _NM_IN_SET_EVAL_3(op, _x, y1, y2, y3)                       \
    (   (_x == (y1))                                                \
     op (_x == (y2))                                                \
     op (_x == (y3))                                                \
    )

#define _NM_IN_SET_EVAL_4(op, _x, y1, y2, y3, y4)                   \
    (   (_x == (y1))                                                \
     op (_x == (y2))                                                \
     op (_x == (y3))                                                \
     op (_x == (y4))                                                \
    )

#define _NM_IN_SET_EVAL_5(op, _x, y1, y2, y3, y4, y5)               \
    (   (_x == (y1))                                                \
     op (_x == (y2))                                                \
     op (_x == (y3))                                                \
     op (_x == (y4))                                                \
     op (_x == (y5))                                                \
    )

#define _NM_IN_SET_EVAL_6(op, _x, y1, y2, y3, y4, y5, y6)           \
    (   (_x == (y1))                                                \
     op (_x == (y2))                                                \
     op (_x == (y3))                                                \
     op (_x == (y4))                                                \
     op (_x == (y5))                                                \
     op (_x == (y6))                                                \
    )

#define _NM_IN_SET_EVAL_N2(op, _x, n, ...)        _NM_IN_SET_EVAL_##n(op, _x, __VA_ARGS__)
#define _NM_IN_SET_EVAL_N(op, x, n, ...)                            \
    ({                                                              \
        typeof(x) _x = (x);                                         \
        !!_NM_IN_SET_EVAL_N2(op, _x, n, __VA_ARGS__);               \
    })

/* Beware that this does short-circuit evaluation (use "||" instead of "|")
 * which has a possibly unexpected non-function-like behavior.
 * Use NM_IN_SET_SE if you need all arguments to be evaluted. */
#define NM_IN_SET(x, ...)               _NM_IN_SET_EVAL_N(||, x, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/* "SE" stands for "side-effect". Contrary to NM_IN_SET(), this does not do
 * short-circuit evaluation, which can make a difference if the arguments have
 * side-effects. */
#define NM_IN_SET_SE(x, ...)            _NM_IN_SET_EVAL_N(|, x, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/********************************************************/

static inline gboolean
_NM_IN_STRSET_streq (const char *x, const char *s)
{
	return s && strcmp (x, s) == 0;
}

#define _NM_IN_STRSET_EVAL_1(op, _x, y1)                            \
    _NM_IN_STRSET_streq (_x, y1)

#define _NM_IN_STRSET_EVAL_2(op, _x, y1, y2)                        \
    (   _NM_IN_STRSET_streq (_x, y1)                                \
     op _NM_IN_STRSET_streq (_x, y2)                                \
    )

#define _NM_IN_STRSET_EVAL_3(op, _x, y1, y2, y3)                    \
    (   _NM_IN_STRSET_streq (_x, y1)                                \
     op _NM_IN_STRSET_streq (_x, y2)                                \
     op _NM_IN_STRSET_streq (_x, y3)                                \
    )

#define _NM_IN_STRSET_EVAL_4(op, _x, y1, y2, y3, y4)                \
    (   _NM_IN_STRSET_streq (_x, y1)                                \
     op _NM_IN_STRSET_streq (_x, y2)                                \
     op _NM_IN_STRSET_streq (_x, y3)                                \
     op _NM_IN_STRSET_streq (_x, y4)                                \
    )

#define _NM_IN_STRSET_EVAL_5(op, _x, y1, y2, y3, y4, y5)            \
    (   _NM_IN_STRSET_streq (_x, y1)                                \
     op _NM_IN_STRSET_streq (_x, y2)                                \
     op _NM_IN_STRSET_streq (_x, y3)                                \
     op _NM_IN_STRSET_streq (_x, y4)                                \
     op _NM_IN_STRSET_streq (_x, y5)                                \
    )

#define _NM_IN_STRSET_EVAL_6(op, _x, y1, y2, y3, y4, y5, y6)        \
    (   _NM_IN_STRSET_streq (_x, y1)                                \
     op _NM_IN_STRSET_streq (_x, y2)                                \
     op _NM_IN_STRSET_streq (_x, y3)                                \
     op _NM_IN_STRSET_streq (_x, y4)                                \
     op _NM_IN_STRSET_streq (_x, y5)                                \
     op _NM_IN_STRSET_streq (_x, y6)                                \
    )

#define _NM_IN_STRSET_EVAL_N2(op, _x, n, ...) _NM_IN_STRSET_EVAL_##n(op, _x, __VA_ARGS__)
#define _NM_IN_STRSET_EVAL_N(op, x, n, ...)                       \
    ({                                                            \
        const char *_x = (x);                                     \
        (   ((_x == NULL) && _NM_IN_SET_EVAL_N2    (op, (const char *) NULL, n, __VA_ARGS__)) \
         || ((_x != NULL) && _NM_IN_STRSET_EVAL_N2 (op, _x,                  n, __VA_ARGS__)) \
        ); \
    })

/* Beware that this does short-circuit evaluation (use "||" instead of "|")
 * which has a possibly unexpected non-function-like behavior.
 * Use NM_IN_STRSET_SE if you need all arguments to be evaluted. */
#define NM_IN_STRSET(x, ...)               _NM_IN_STRSET_EVAL_N(||, x, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/* "SE" stands for "side-effect". Contrary to NM_IN_STRSET(), this does not do
 * short-circuit evaluation, which can make a difference if the arguments have
 * side-effects. */
#define NM_IN_STRSET_SE(x, ...)            _NM_IN_STRSET_EVAL_N(|, x, NM_NARG (__VA_ARGS__), __VA_ARGS__)

/*****************************************************************************/

#define nm_streq(s1, s2)  (strcmp (s1, s2) == 0)
#define nm_streq0(s1, s2) (g_strcmp0 (s1, s2) == 0)

/*****************************************************************************/

#define nm_str_not_empty(str) \
	({ \
		/* implemented as macro to preserve constness */ \
		typeof (str) __str = (str); \
		_nm_unused const char *__str_type_check = __str; \
		((__str && __str[0]) ? __str : ((char *) NULL)); \
	})

static inline char *
nm_strdup_not_empty (const char *str)
{
	return str && str[0] ? g_strdup (str) : NULL;
}

/*****************************************************************************/

#define NM_PRINT_FMT_QUOTED(cond, prefix, str, suffix, str_else) \
	(cond) ? (prefix) : "", \
	(cond) ? (str) : (str_else), \
	(cond) ? (suffix) : ""
#define NM_PRINT_FMT_QUOTE_STRING(arg) NM_PRINT_FMT_QUOTED((arg), "\"", (arg), "\"", "(null)")

/*****************************************************************************/

/* glib/C provides the following kind of assertions:
 *   - assert() -- disable with NDEBUG
 *   - g_return_if_fail() -- disable with G_DISABLE_CHECKS
 *   - g_assert() -- disable with G_DISABLE_ASSERT
 * but they are all enabled by default and usually even production builds have
 * these kind of assertions enabled. It also means, that disabling assertions
 * is an untested configuration, and might have bugs.
 *
 * Add our own assertion macro nm_assert(), which is disabled by default and must
 * be explicitly enabled. They are useful for more expensive checks or checks that
 * depend less on runtime conditions (that is, are generally expected to be true). */

#ifndef NM_MORE_ASSERTS
#define NM_MORE_ASSERTS 0
#endif

#if NM_MORE_ASSERTS
#define nm_assert(cond) G_STMT_START { g_assert (cond); } G_STMT_END
#define nm_assert_not_reached() G_STMT_START { g_assert_not_reached (); } G_STMT_END
#else
#define nm_assert(cond) G_STMT_START { if (FALSE) { if (cond) { } } } G_STMT_END
#define nm_assert_not_reached() G_STMT_START { ; } G_STMT_END
#endif

/*****************************************************************************/

#define NM_GOBJECT_PROPERTIES_DEFINE_BASE(...) \
typedef enum { \
	_PROPERTY_ENUMS_0, \
	__VA_ARGS__ \
	_PROPERTY_ENUMS_LAST, \
} _PropertyEnums; \
static GParamSpec *obj_properties[_PROPERTY_ENUMS_LAST] = { NULL, }

#define NM_GOBJECT_PROPERTIES_DEFINE(obj_type, ...) \
NM_GOBJECT_PROPERTIES_DEFINE_BASE (__VA_ARGS__); \
static inline void \
_notify (obj_type *obj, _PropertyEnums prop) \
{ \
	nm_assert (G_IS_OBJECT (obj)); \
	nm_assert ((gsize) prop < G_N_ELEMENTS (obj_properties)); \
	g_object_notify_by_pspec ((GObject *) obj, obj_properties[prop]); \
}

/*****************************************************************************/

#define __NM_GET_PRIVATE(self, type, is_check, result_cmd) \
	({ \
		/* preserve the const-ness of self. Unfortunately, that
		 * way, @self cannot be a void pointer */ \
		typeof (self) _self = (self); \
		\
		/* Get compiler error if variable is of wrong type */ \
		_nm_unused const type *_self2 = (_self); \
		\
		nm_assert (is_check (_self)); \
		( result_cmd ); \
	})

#define _NM_GET_PRIVATE(self, type, is_check)     __NM_GET_PRIVATE(self, type, is_check, &_self->_priv)
#define _NM_GET_PRIVATE_PTR(self, type, is_check) __NM_GET_PRIVATE(self, type, is_check,  _self->_priv)

/*****************************************************************************/

static inline gpointer
nm_g_object_ref (gpointer obj)
{
	/* g_object_ref() doesn't accept NULL. */
	if (obj)
		g_object_ref (obj);
	return obj;
}

static inline void
nm_g_object_unref (gpointer obj)
{
	/* g_object_unref() doesn't accept NULL. Usully, we workaround that
	 * by using g_clear_object(), but sometimes that is not convinient
	 * (for example as as destroy function for a hash table that can contain
	 * NULL values). */
	if (obj)
		g_object_unref (obj);
}

static inline gboolean
nm_clear_g_source (guint *id)
{
	if (id && *id) {
		g_source_remove (*id);
		*id = 0;
		return TRUE;
	}
	return FALSE;
}

static inline gboolean
nm_clear_g_signal_handler (gpointer self, gulong *id)
{
	if (id && *id) {
		g_signal_handler_disconnect (self, *id);
		*id = 0;
		return TRUE;
	}
	return FALSE;
}

static inline gboolean
nm_clear_g_variant (GVariant **variant)
{
	if (variant && *variant) {
		g_variant_unref (*variant);
		*variant = NULL;
		return TRUE;
	}
	return FALSE;
}

static inline gboolean
nm_clear_g_cancellable (GCancellable **cancellable)
{
	if (cancellable && *cancellable) {
		g_cancellable_cancel (*cancellable);
		g_object_unref (*cancellable);
		*cancellable = NULL;
		return TRUE;
	}
	return FALSE;
}

/*****************************************************************************/

/* Determine whether @x is a power of two (@x being an integer type).
 * For the special cases @x equals zero or one, it also returns true.
 * For negative @x, always returns FALSE. That only applies, if the data
 * type of @x is signed. */
#define nm_utils_is_power_of_two(x) ({ \
		typeof(x) __x = (x); \
		\
		/* Check if the value is negative. In that case, return FALSE.
		 * The first expression is a compile time constant, depending on whether
		 * the type is signed. The second expression is a clumsy way for (__x >= 0),
		 * which causes a compiler warning for unsigned types. */ \
		    ( ( ((typeof(__x)) -1) > ((typeof(__x)) 0) ) || (__x > 0) || (__x == 0) ) \
		 && ((__x & (__x - 1)) == 0); \
	})

/*****************************************************************************/

/* check if @flags has exactly one flag (@check) set. You should call this
 * only with @check being a compile time constant and a power of two. */
#define NM_FLAGS_HAS(flags, check)  \
    ( (G_STATIC_ASSERT_EXPR ( ((check) != 0) && ((check) & ((check)-1)) == 0 )), (NM_FLAGS_ANY ((flags), (check))) )

#define NM_FLAGS_ANY(flags, check)  ( ( ((flags) & (check)) != 0       ) ? TRUE : FALSE )
#define NM_FLAGS_ALL(flags, check)  ( ( ((flags) & (check)) == (check) ) ? TRUE : FALSE )

#define NM_FLAGS_SET(flags, val)  ({ \
		const typeof(flags) _flags = (flags); \
		const typeof(flags) _val = (val); \
		\
		_flags | _val; \
	})

#define NM_FLAGS_UNSET(flags, val)  ({ \
		const typeof(flags) _flags = (flags); \
		const typeof(flags) _val = (val); \
		\
		_flags & (~_val); \
	})

#define NM_FLAGS_ASSIGN(flags, val, assign)  ({ \
		const typeof(flags) _flags = (flags); \
		const typeof(flags) _val = (val); \
		\
		(assign) \
			? _flags | (_val) \
			: _flags & (~_val); \
	})

/*****************************************************************************/

#define _NM_BACKPORT_SYMBOL_IMPL(VERSION, RETURN_TYPE, ORIG_FUNC, VERSIONED_FUNC, ARGS_TYPED, ARGS) \
RETURN_TYPE VERSIONED_FUNC ARGS_TYPED; \
RETURN_TYPE VERSIONED_FUNC ARGS_TYPED \
{ \
    return ORIG_FUNC ARGS; \
} \
RETURN_TYPE ORIG_FUNC ARGS_TYPED; \
__asm__(".symver "G_STRINGIFY(VERSIONED_FUNC)", "G_STRINGIFY(ORIG_FUNC)"@"G_STRINGIFY(VERSION))

#define NM_BACKPORT_SYMBOL(VERSION, RETURN_TYPE, FUNC, ARGS_TYPED, ARGS) \
_NM_BACKPORT_SYMBOL_IMPL(VERSION, RETURN_TYPE, FUNC, _##FUNC##_##VERSION, ARGS_TYPED, ARGS)

/*****************************************************************************/

static inline char *
nm_strstrip (char *str)
{
	/* g_strstrip doesn't like NULL. */
	return str ? g_strstrip (str) : NULL;
}

/* g_ptr_array_sort()'s compare function takes pointers to the
 * value. Thus, you cannot use strcmp directly. You can use
 * nm_strcmp_p().
 *
 * Like strcmp(), this function is not forgiving to accept %NULL. */
static inline int
nm_strcmp_p (gconstpointer a, gconstpointer b)
{
	const char *s1 = *((const char **) a);
	const char *s2 = *((const char **) b);

	return strcmp (s1, s2);
}

/* like nm_strcmp_p(), suitable for g_ptr_array_sort_with_data().
 * g_ptr_array_sort() just casts nm_strcmp_p() to a function of different
 * signature. I guess, in glib there are knowledgeable people that ensure
 * that this additional argument doesn't cause problems due to different ABI
 * for every architecture that glib supports.
 * For NetworkManager, we'd rather avoid such stunts.
 **/
static inline int
nm_strcmp_p_with_data (gconstpointer a, gconstpointer b, gpointer user_data)
{
	const char *s1 = *((const char **) a);
	const char *s2 = *((const char **) b);

	return strcmp (s1, s2);
}

/*****************************************************************************/

/* Taken from systemd's UNIQ_T and UNIQ macros. */

#define NM_UNIQ_T(x, uniq) G_PASTE(__unique_prefix_, G_PASTE(x, uniq))
#define NM_UNIQ __COUNTER__

/*****************************************************************************/

/* glib's MIN()/MAX() macros don't have function-like behavior, in that they evaluate
 * the argument possibly twice.
 *
 * Taken from systemd's MIN()/MAX() macros. */

#define NM_MIN(a, b) __NM_MIN(NM_UNIQ, a, NM_UNIQ, b)
#define __NM_MIN(aq, a, bq, b) \
	({ \
		typeof (a) NM_UNIQ_T(A, aq) = (a); \
		typeof (b) NM_UNIQ_T(B, bq) = (b); \
		((NM_UNIQ_T(A, aq) < NM_UNIQ_T(B, bq)) ? NM_UNIQ_T(A, aq) : NM_UNIQ_T(B, bq)); \
	})

#define NM_MAX(a, b) __NM_MAX(NM_UNIQ, a, NM_UNIQ, b)
#define __NM_MAX(aq, a, bq, b) \
	({ \
		typeof (a) NM_UNIQ_T(A, aq) = (a); \
		typeof (b) NM_UNIQ_T(B, bq) = (b); \
		((NM_UNIQ_T(A, aq) > NM_UNIQ_T(B, bq)) ? NM_UNIQ_T(A, aq) : NM_UNIQ_T(B, bq)); \
	})

#define NM_CLAMP(x, low, high) __NM_CLAMP(NM_UNIQ, x, NM_UNIQ, low, NM_UNIQ, high)
#define __NM_CLAMP(xq, x, lowq, low, highq, high) \
	({ \
		typeof(x)NM_UNIQ_T(X,xq) = (x); \
		typeof(low) NM_UNIQ_T(LOW,lowq) = (low); \
		typeof(high) NM_UNIQ_T(HIGH,highq) = (high); \
		\
		( (NM_UNIQ_T(X,xq) > NM_UNIQ_T(HIGH,highq)) \
		  ? NM_UNIQ_T(HIGH,highq) \
		  : (NM_UNIQ_T(X,xq) < NM_UNIQ_T(LOW,lowq)) \
		     ? NM_UNIQ_T(LOW,lowq) \
		     : NM_UNIQ_T(X,xq)); \
	})

/*****************************************************************************/

static inline guint
nm_encode_version (guint major, guint minor, guint micro) {
	/* analog to the preprocessor macro NM_ENCODE_VERSION(). */
	return (major << 16) | (minor << 8) | micro;
}

static inline void
nm_decode_version (guint version, guint *major, guint *minor, guint *micro) {
	*major = (version & 0xFFFF0000u) >> 16;
	*minor = (version & 0x0000FF00u) >>  8;
	*micro = (version & 0x000000FFu);
}
/*****************************************************************************/

/* if @str is NULL, return "(null)". Otherwise, allocate a buffer using
 * alloca() of size @bufsize and fill it with @str. @str will be quoted with
 * single quote, and in case @str is too long, the final quote will be '^'. */
#define nm_strquote_a(bufsize, str) \
	({ \
		G_STATIC_ASSERT ((bufsize) >= 6); \
		const gsize _BUFSIZE = (bufsize); \
		const char *const _s = (str); \
		char *_r; \
		gsize _l; \
		gboolean _truncated; \
		\
		nm_assert (_BUFSIZE >= 6); \
		\
		if (_s) { \
			_l = strlen (_s) + 3; \
			if ((_truncated = (_BUFSIZE < _l))) \
				_l = _BUFSIZE; \
			\
			_r = g_alloca (_l); \
			_r[0] = '\''; \
			memcpy (&_r[1], _s, _l - 3); \
			_r[_l - 2] = _truncated ? '^' : '\''; \
			_r[_l - 1] = '\0'; \
		} else \
			_r = "(null)"; \
		_r; \
	})

#define nm_sprintf_buf(buf, format, ...) ({ \
		char * _buf = (buf); \
		\
		/* some static assert trying to ensure that the buffer is statically allocated.
		 * It disallows a buffer size of sizeof(gpointer) to catch that. */ \
		G_STATIC_ASSERT (G_N_ELEMENTS (buf) == sizeof (buf) && sizeof (buf) != sizeof (char *)); \
		g_snprintf (_buf, sizeof (buf), \
		            ""format"", ##__VA_ARGS__); \
		_buf; \
	})

#define nm_sprintf_bufa(n_elements, format, ...) \
	({ \
		char *_buf; \
		\
		G_STATIC_ASSERT (sizeof (char[MAX ((n_elements), 1)]) == (n_elements)); \
		_buf = g_alloca (n_elements); \
		g_snprintf (_buf, n_elements, \
		            ""format"", ##__VA_ARGS__); \
		_buf; \
	})

/*****************************************************************************/

/**
 * The boolean type _Bool is C99 while we mostly stick to C89. However, _Bool is too
 * convinient to miss and is effectively available in gcc and clang. So, just use it.
 *
 * Usually, one would include "stdbool.h" to get the "bool" define which aliases
 * _Bool. We provide this define here, because we want to make use of it anywhere.
 * (also, stdbool.h is again C99).
 *
 * Using _Bool has advantages over gboolean:
 *
 * - commonly _Bool is one byte large, instead of gboolean's 4 bytes (because gboolean
 *   is a typedef for gint). Especially when having boolean fields in a struct, we can
 *   thereby easily save some space.
 *
 * - _Bool type guarantees that two "true" expressions compare equal. E.g. the follwing
 *   will not work:
 *        gboolean v1 = 1;
 *        gboolean v2 = 2;
 *        g_assert_cmpint (v1, ==, v2); // will fail
 *   For that, we often to use !! to coerce gboolean values to 0 or 1:
 *        g_assert_cmpint (!!v2, ==, TRUE);
 *   With _Bool type, this will be handled properly by the compiler.
 *
 * - For structs, we might want to safe even more space and use bitfields:
 *       struct s1 {
 *           gboolean v1:1;
 *       };
 *   But the problem here is that gboolean is signed, so that
 *   v1 will be either 0 or -1 (not 1, TRUE). Thus, the following
 *   fails:
 *      struct s1 s = { .v1 = TRUE, };
 *      g_assert_cmpint (s1.v1, ==, TRUE);
 *   It will however work just fine with bool/_Bool while retaining the
 *   notion of having a boolean value.
 *
 * Also, add the defines for "true" and "false". Those are nicely highlighted by the editor
 * as special types, contrary to glib's "TRUE"/"FALSE".
 */

#ifndef bool
#define bool _Bool
#define true    1
#define false   0
#endif

/*****************************************************************************/

#endif /* __NM_MACROS_INTERNAL_H__ */
