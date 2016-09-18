dnl GIT_SHA_RECORD($1, $2)
dnl
dnl $1: the name of the assigned variable. For example NM_GIT_SHA,
dnl     NMA_GIT_SHA, LIBNL_GIT_SHA.
dnl $2: by default, a define to config.h is added. This can be
dnl     suppressed by passing "no-config-h".
dnl
AC_DEFUN([GIT_SHA_RECORD], [
    m4_define([git_sha_record_v],
              [m4_esyscmd([ ( [ -d ./.git/ ] && [ "$(readlink -f ./.git/)" = "$(readlink -f "$(git rev-parse --git-dir 2>/dev/null)" 2>/dev/null)" ] && git rev-parse --verify -q HEAD 2>/dev/null ) || true ])])
$1=git_sha_record_v
if test ""$2"" != "no-config-h" ; then
    AC_DEFINE_UNQUOTED($1,"$$1",[git commit id of the original source code version])
fi
])
