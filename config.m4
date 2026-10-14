dnl config.m4 for extension ssh2

PHP_ARG_WITH(ssh2, for ssh2 support,
[  --with-ssh2=[DIR]       Include ssh2 support])

if test "$PHP_SSH2" != "no"; then
  SEARCH_PATH="/usr/local /usr /opt/homebrew /opt/homebrew/opt/libssh2"
  SEARCH_FOR="/include/libssh2.h"
  if test -r $PHP_SSH2/$SEARCH_FOR; then # path given as parameter
    SSH2_DIR=$PHP_SSH2
  else
    AC_MSG_CHECKING([for ssh2 files in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        SSH2_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi
  
  if test -z "$SSH2_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([The required libssh2 library was not found.  You can obtain that package from http://sourceforge.net/projects/libssh2/])
  fi

  PHP_ADD_INCLUDE($SSH2_DIR/include)

  saved_CPPFLAGS=$CPPFLAGS
  CPPFLAGS="-I$SSH2_DIR/include $CPPFLAGS"
  AC_MSG_CHECKING([for libssh2 version >= 1.9.0])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <libssh2.h>
    #if LIBSSH2_VERSION_NUM < 0x010900
    #error libssh2 1.9.0 or newer is required
    #endif
  ]], [[]])], [
    AC_MSG_RESULT([yes])
  ], [
    AC_MSG_ERROR([libssh2 version >= 1.9.0 not found])
  ])
  CPPFLAGS=$saved_CPPFLAGS

  PHP_CHECK_LIBRARY(ssh2,libssh2_session_hostkey,
  [
    PHP_ADD_LIBRARY_WITH_PATH(ssh2, $SSH2_DIR/lib, SSH2_SHARED_LIBADD)
    AC_DEFINE(HAVE_SSH2LIB,1,[Have libssh2])
  ],[
    AC_MSG_ERROR([libssh2 library not found or too old; version 1.9.0 or newer is required])
  ],[
    -L$SSH2_DIR/lib -lm 
  ])
  
  PHP_CHECK_LIBRARY(ssh2,libssh2_agent_init,
  [
    AC_DEFINE(PHP_SSH2_AGENT_AUTH, 1, [Have libssh2 with ssh-agent support])
  ],[
    AC_MSG_ERROR([libssh2_agent_init not found; ensure the linked libssh2 matches the 1.9.0 or newer headers])
  ],[
    -L$SSH2_DIR/lib -lm
  ])

  PHP_CHECK_LIBRARY(ssh2,libssh2_session_set_timeout,
  [
    AC_DEFINE(PHP_SSH2_SESSION_TIMEOUT, 1, [Have libssh2 with session timeout support])
  ],[
    AC_MSG_ERROR([libssh2_session_set_timeout not found; ensure the linked libssh2 matches the 1.9.0 or newer headers])
  ],[
    -L$SSH2_DIR/lib -lm 
  ])

  PHP_CHECK_LIBRARY(ssh2,libssh2_keepalive_config,
  [
    AC_DEFINE(PHP_SSH2_KEEPALIVE, 1, [Have libssh2 with keepalive support])
  ],[
    AC_MSG_ERROR([libssh2_keepalive_config not found; ensure the linked libssh2 matches the 1.9.0 or newer headers])
  ],[
    -L$SSH2_DIR/lib -lm
  ])

  PHP_CHECK_LIBRARY(ssh2,libssh2_channel_signal_ex,
  [
    AC_DEFINE(PHP_SSH2_CHANNEL_SIGNAL, 1, [Have libssh2 with channel signal support])
  ],[
    AC_MSG_ERROR([libssh2_channel_signal_ex not found; ensure the linked libssh2 matches the 1.9.0 or newer headers])
  ],[
    -L$SSH2_DIR/lib -lm
  ])

  PHP_SUBST(SSH2_SHARED_LIBADD)

  PHP_NEW_EXTENSION(ssh2, ssh2.c ssh2_fopen_wrappers.c ssh2_sftp.c, $ext_shared)
fi
