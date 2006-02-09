dnl $Id$
dnl config.m4 for extension ssh2

PHP_ARG_WITH(ssh2, for ssh2 support,
[  --with-ssh2=[DIR]       Include ssh2 support])

if test "$PHP_SSH2" != "no"; then
  SEARCH_PATH="/usr/local /usr"
  SEARCH_FOR="/include/libssh2.h"
  if test -r $PHP_SSH2/; then # path given as parameter
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

  LIBNAME=ssh2
  LIBSYMBOL=libssh2_banner_set

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $SSH2_DIR/lib, SSH2_SHARED_LIBADD)
    AC_DEFINE(HAVE_SSH2LIB,1,[Have libssh2])
  ],[
    AC_MSG_ERROR([libssh2 version >= 0.4 not found])
  ],[
    -L$SSH2_DIR/lib -lm 
  ])

  PHP_CHECK_LIBRARY($LIBNAME,libssh2_channel_forward_listen_ex,
  [
    AC_DEFINE(PHP_SSH2_REMOTE_FORWARDING, 1, [Have libssh2 with remote forwarding])
  ],[
    AC_MSG_WARN([libssh2 <= 0.4, remote forwarding not enabled])
  ],[
    -L$SSH2_DIR/lib -lm 
  ])

  PHP_CHECK_LIBRARY($LIBNAME,libssh2_userauth_hostbased_fromfile_ex,
  [
    AC_DEFINE(PHP_SSH2_HOSTBASED_AUTH, 1, [Have libssh2 with hostbased authentication])
  ],[
    AC_MSG_WARN([libssh2 <= 0.6, hostbased authentication not enabled])
  ],[
    -L$SSH2_DIR/lib -lm 
  ])

  PHP_CHECK_LIBRARY($LIBNAME,libssh2_poll,
  [
    AC_DEFINE(PHP_SSH2_POLL, 1, [Have libssh2 with poll() support])
  ],[
    AC_MSG_WARN([libssh2 <= 0.7, poll support not enabled])
  ],[
    -L$SSH2_DIR/lib -lm 
  ])

  PHP_CHECK_LIBRARY($LIBNAME,libssh2_publickey_init,
  [
    AC_DEFINE(PHP_SSH2_PUBLICKEY_SUBSYSTEM, 1, [Have libssh2 with publickey subsystem support])
  ],[
    AC_MSG_WARN([libssh2 <= 0.11, publickey subsystem support not enabled])
  ],[
    -L$SSH2_DIR/lib -lm 
  ])
  
  PHP_SUBST(SSH2_SHARED_LIBADD)

  PHP_NEW_EXTENSION(ssh2, ssh2.c ssh2_fopen_wrappers.c ssh2_sftp.c, $ext_shared)
fi
