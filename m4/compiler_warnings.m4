dnl Check whether a particular compiler flag works with code provided,
dnl disable it in CFLAGS if the check fails.
AC_DEFUN([NM_COMPILER_WARNING], [
	CFLAGS_SAVED="$CFLAGS"
	CFLAGS="$CFLAGS -Werror -W$1"
	AC_MSG_CHECKING(whether -W$1 works)

	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[]])], [
		AC_COMPILE_IFELSE([AC_LANG_SOURCE([[$2]])], [
			AC_MSG_RESULT(yes)
			CFLAGS="$CFLAGS_SAVED -W$1"
		],[
			AC_MSG_RESULT(no)
			CFLAGS="$CFLAGS_SAVED -Wno-$1"
		])
	],[
		AC_MSG_RESULT(not supported)
		CFLAGS="$CFLAGS_SAVED"
	])
])

AC_DEFUN([NM_COMPILER_WARNINGS],
[AC_ARG_ENABLE(more-warnings,
	AS_HELP_STRING([--enable-more-warnings], [Possible values: no/yes/error]),
	set_more_warnings="$enableval",set_more_warnings=yes)
AC_MSG_CHECKING(for more warnings)
if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
	AC_MSG_RESULT(yes)

	dnl This is enabled in clang by default, makes little sense,
	dnl and causes the build to abort with -Werror.
	CFLAGS_SAVED="$CFLAGS"
	CFLAGS="$CFLAGS -Qunused-arguments"
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([])], [], CFLAGS="$CFLAGS_SAVED")
	unset CFLAGS_SAVED

	dnl clang only warns about unknown warnings, unless
	dnl called with "-Werror=unknown-warning-option"
	dnl Test if the compiler supports that, and if it does
	dnl attach it to the CFLAGS.
	NM_COMPILER_WARNING([unknown-warning-option], [])

	CFLAGS_SAVED="$CFLAGS"
	CFLAGS_MORE_WARNINGS="-Wall -std=gnu89"

	if test "x$set_more_warnings" = xerror; then
		CFLAGS_MORE_WARNINGS="$CFLAGS_MORE_WARNINGS -Werror"
	fi

	for option in -Wshadow -Wmissing-declarations -Wmissing-prototypes \
		      -Wdeclaration-after-statement -Wformat-security \
		      -Wfloat-equal -Wno-unused-parameter -Wno-sign-compare \
		      -Wno-duplicate-decl-specifier \
		      -Wstrict-prototypes \
		      -fno-strict-aliasing -Wno-unused-but-set-variable \
		      -Wundef -Wimplicit-function-declaration \
		      -Wpointer-arith -Winit-self \
		      -Wmissing-include-dirs -Wno-pragmas; do
		dnl GCC 4.4 does not warn when checking for -Wno-* flags (https://gcc.gnu.org/wiki/FAQ#wnowarning)
		CFLAGS="-Werror $CFLAGS_MORE_WARNINGS $(printf '%s' "$option" | sed 's/^-Wno-/-W/')  $CFLAGS_SAVED"
		AC_MSG_CHECKING([whether compiler understands $option])
		AC_TRY_COMPILE([], [],
			has_option=yes,
			has_option=no,)
		if test $has_option != no; then
			CFLAGS_MORE_WARNINGS="$CFLAGS_MORE_WARNINGS $option"
		fi
		AC_MSG_RESULT($has_option)
		unset has_option
	done
	unset option

	CFLAGS="$CFLAGS_SAVED"
	unset CFLAGS_SAVED

	dnl Disable warnings triggered by known compiler problems

	dnl https://bugzilla.gnome.org/show_bug.cgi?id=745821
	NM_COMPILER_WARNING([unknown-attributes], [#include <glib.h>])

	dnl https://bugzilla.gnome.org/show_bug.cgi?id=744473
	NM_COMPILER_WARNING([typedef-redefinition], [#include <gio/gio.h>])

	dnl https://llvm.org/bugs/show_bug.cgi?id=21614
	NM_COMPILER_WARNING([array-bounds],
		[#include <string.h>]
		[void f () { strcmp ("something", "0"); }]
	)

	dnl https://llvm.org/bugs/show_bug.cgi?id=22949
	NM_COMPILER_WARNING([parentheses-equality],
		[#include <sys/wait.h>]
		[void f () { if (WIFCONTINUED(0)) return; }]
	)

	dnl systemd-dhcp's log_internal macro and our handle_warn are sometimes
	dnl used in void context,u sometimes in int. Makes clang unhappy.
	NM_COMPILER_WARNING([unused-value],
		[#define yolo ({ (666 + 666); })]
		[int f () { int i = yolo; yolo; return i; }]
	)

	CFLAGS="$CFLAGS_MORE_WARNINGS $CFLAGS"
else
	AC_MSG_RESULT(no)
fi
])
