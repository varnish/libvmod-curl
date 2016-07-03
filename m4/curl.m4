# curl.m4
#
# serial 1

AC_DEFUN([AX_CURLOPT_CHECK], [
  save_CFLAGS="${CFLAGS}"
  save_LIBS="${LIBS}"
  CFLAGS="${CFLAGS} ${CURL_CFLAGS}"
  LIBS="${LIBS} ${CURL_LIBS}"
  AC_CACHE_CHECK([if curl supports $1],
    [ax_cv_curl_$1],
    [AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM([[
#include <curl/curl.h>
      ]],[[
CURL *curl;
curl = curl_easy_init();
curl_easy_setopt(curl, $1, 10);
      ]])],
      [ax_cv_curl_$1=yes],
      [ax_cv_curl_$1=no])
    ])
  if test "$ax_cv_curl_$1" = "yes"; then
    AC_DEFINE([HAVE_$1], [1], [Define if curl supports $1])
  fi
  CFLAGS="${save_CFLAGS}"
  LIBS="${save_LIBS}"
])
