/*
  +----------------------------------------------------------------------+
  | PHP Version 4                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2006 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available at through the world-wide-web at                           |
  | http://www.php.net/license/3_01.txt.                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Sara Golemon <pollita@php.net>                               |
  +----------------------------------------------------------------------+

  $Id$
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ssh2.h"
#include "ext/standard/php_string.h"

/* *************************
   * Resource Housekeeping *
   ************************* */

void php_ssh2_sftp_dtor(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	php_ssh2_sftp_data *data = (php_ssh2_sftp_data*)rsrc->ptr;

	if (!data) {
		return;
	}

	libssh2_sftp_shutdown(data->sftp);

	zend_list_delete(data->session_rsrcid);

	efree(data);
}

/* *****************
   * SFTP File Ops *
   ***************** */

inline unsigned long php_ssh2_parse_fopen_modes(char *openmode) {
	unsigned long flags = 0;

	if (strchr(openmode, 'a')) {
		flags |= LIBSSH2_FXF_APPEND;
	}

	if (strchr(openmode, 'w')) {
		flags |= LIBSSH2_FXF_WRITE | LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_CREAT;
	}

	if (strchr(openmode, 'r')) {
		flags |= LIBSSH2_FXF_READ;
	}

	if (strchr(openmode, '+')) {
		flags |= LIBSSH2_FXF_READ | LIBSSH2_FXF_WRITE;
	}

	if (strchr(openmode, 'x')) {
		flags |= LIBSSH2_FXF_WRITE | LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_EXCL | LIBSSH2_FXF_CREAT;
	}

	return flags;
}

inline int php_ssh2_sftp_attr2ssb(php_stream_statbuf *ssb, LIBSSH2_SFTP_ATTRIBUTES *attrs)
{
	memset(ssb, 0, sizeof(php_stream_statbuf));
	if (attrs->flags & LIBSSH2_SFTP_ATTR_SIZE) {
		ssb->sb.st_size = attrs->filesize;
	}
	
	if (attrs->flags & LIBSSH2_SFTP_ATTR_UIDGID) {
		ssb->sb.st_uid = attrs->uid;
		ssb->sb.st_gid = attrs->gid;
	}
	if (attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
		ssb->sb.st_mode = attrs->permissions;
	}
	if (attrs->flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
		ssb->sb.st_atime = attrs->atime;
		ssb->sb.st_mtime = attrs->mtime;
	}

	return 0;
}

typedef struct _php_ssh2_sftp_handle_data {
	LIBSSH2_SFTP_HANDLE *handle;

	long sftp_rsrcid;
} php_ssh2_sftp_handle_data;

/* {{{ php_ssh2_sftp_stream_write
 */
static size_t php_ssh2_sftp_stream_write(php_stream *stream, const char *buf, size_t count TSRMLS_DC)
{
	php_ssh2_sftp_handle_data *data = (php_ssh2_sftp_handle_data*)stream->abstract;
	ssize_t bytes_written;

	bytes_written = libssh2_sftp_write(data->handle, buf, count);

	return (size_t)(bytes_written<0 ? 0 : bytes_written);
}
/* }}} */

/* {{{ php_ssh2_sftp_stream_read
 */
static size_t php_ssh2_sftp_stream_read(php_stream *stream, char *buf, size_t count TSRMLS_DC)
{
	php_ssh2_sftp_handle_data *data = (php_ssh2_sftp_handle_data*)stream->abstract;
	ssize_t bytes_read;

	bytes_read = libssh2_sftp_read(data->handle, buf, count);

	stream->eof = (bytes_read <= 0 && bytes_read != LIBSSH2_ERROR_EAGAIN);

	return (size_t)(bytes_read<0 ? 0 : bytes_read);
}
/* }}} */

/* {{{ php_ssh2_sftp_stream_close
 */
static int php_ssh2_sftp_stream_close(php_stream *stream, int close_handle TSRMLS_DC)
{
	php_ssh2_sftp_handle_data *data = (php_ssh2_sftp_handle_data*)stream->abstract;

	libssh2_sftp_close(data->handle);
	zend_list_delete(data->sftp_rsrcid);
	efree(data);

	return 0;
}
/* }}} */

/* {{{ php_ssh2_sftp_stream_seek
 */
static int php_ssh2_sftp_stream_seek(php_stream *stream, off_t offset, int whence, off_t *newoffset TSRMLS_DC)
{
	php_ssh2_sftp_handle_data *data = (php_ssh2_sftp_handle_data*)stream->abstract;

	switch (whence) {
		case SEEK_END:
		{
			LIBSSH2_SFTP_ATTRIBUTES attrs;

			if (libssh2_sftp_fstat(data->handle, &attrs)) {
				return -1;
			}
			if ((attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) == 0) {
				return -1;
			}
			offset += attrs.filesize;
		}
		case SEEK_CUR:
		{
			off_t current_offset = libssh2_sftp_tell(data->handle);

			if (current_offset < 0) {
				return -1;
			}

			offset += current_offset;
		}
	}

	libssh2_sftp_seek(data->handle, offset);

	if (newoffset) {
		*newoffset = offset;
	}

	return 0;
}
/* }}} */

/* {{{ php_ssh2_sftp_stream_fstat
 */
static int php_ssh2_sftp_stream_fstat(php_stream *stream, php_stream_statbuf *ssb TSRMLS_DC)
{
	php_ssh2_sftp_handle_data *data = (php_ssh2_sftp_handle_data*)stream->abstract;
	LIBSSH2_SFTP_ATTRIBUTES attrs;

	if (libssh2_sftp_fstat(data->handle, &attrs)) {
		return -1;
	}

	return php_ssh2_sftp_attr2ssb(ssb, &attrs);
}
/* }}} */

static php_stream_ops php_ssh2_sftp_stream_ops = {
    php_ssh2_sftp_stream_write,
    php_ssh2_sftp_stream_read,
    php_ssh2_sftp_stream_close,
    NULL, /* flush */
    PHP_SSH2_SFTP_STREAM_NAME,
    php_ssh2_sftp_stream_seek,
    NULL, /* cast */
    php_ssh2_sftp_stream_fstat,
	NULL, /* set_option */
};

/* {{{ php_ssh2_sftp_stream_opener
 */
static php_stream *php_ssh2_sftp_stream_opener(	php_stream_wrapper *wrapper, char *filename, char *mode,
												int options, char **opened_path, php_stream_context *context STREAMS_DC TSRMLS_DC)
{
	php_ssh2_sftp_handle_data *data;
	LIBSSH2_SESSION *session = NULL;
	LIBSSH2_SFTP *sftp = NULL;
	LIBSSH2_SFTP_HANDLE *handle;
	php_stream *stream;
	int resource_id = 0, sftp_rsrcid = 0;
	php_url *resource;
	unsigned long flags;
	long perms = 0644;

	resource = php_ssh2_fopen_wraper_parse_path(filename, "sftp", context, &session, &resource_id, &sftp, &sftp_rsrcid TSRMLS_CC);
	if (!resource || !session || !sftp) {
		return NULL;
	}

	flags = php_ssh2_parse_fopen_modes(mode);

	handle = libssh2_sftp_open(sftp, resource->path, flags, perms);
	if (!handle) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to open %s on remote host", filename);
		php_url_free(resource);
		zend_list_delete(sftp_rsrcid);
		return NULL;
	}

	data = emalloc(sizeof(php_ssh2_sftp_handle_data));
	data->handle = handle;
	data->sftp_rsrcid = sftp_rsrcid;

	stream = php_stream_alloc(&php_ssh2_sftp_stream_ops, data, 0, mode);
	if (!stream) {
		libssh2_sftp_close(handle);
		zend_list_delete(sftp_rsrcid);
		efree(data);
	}
	php_url_free(resource);

	return stream;
}
/* }}} */

/* **********************
   * SFTP Directory Ops *
   ********************** */

/* {{{ php_ssh2_sftp_dirstream_read
 */
static size_t php_ssh2_sftp_dirstream_read(php_stream *stream, char *buf, size_t count TSRMLS_DC)
{
	php_ssh2_sftp_handle_data *data = (php_ssh2_sftp_handle_data*)stream->abstract;
	php_stream_dirent *ent = (php_stream_dirent*)buf;
	int bytesread = libssh2_sftp_readdir(data->handle, ent->d_name, sizeof(ent->d_name) - 1, NULL);
	char *basename = NULL;
	size_t basename_len = 0;

	if (bytesread <= 0) {
		return 0;
	}
	ent->d_name[bytesread] = 0;

#ifdef ZEND_ENGINE_2
	php_basename(ent->d_name, bytesread, NULL, 0, &basename, &basename_len TSRMLS_CC);
#else
/* CURSE YOU BC BREAKS! */
	basename = php_basename(ent->d_name, bytesread, NULL, 0);
	if (basename) {
		basename_len = strlen(basename);
	}
#endif
	if (!basename) {
		return 0;
	}

	if (!basename_len) {
		efree(basename);
		return 0;
	}
	bytesread = MIN(sizeof(ent->d_name) - 1, basename_len);
	memcpy(ent->d_name, basename, bytesread);
	ent->d_name[bytesread] = 0;
	efree(basename);

	return sizeof(php_stream_dirent);
}
/* }}} */

/* {{{ php_ssh2_sftp_dirstream_close
 */
static int php_ssh2_sftp_dirstream_close(php_stream *stream, int close_handle TSRMLS_DC)
{
	php_ssh2_sftp_handle_data *data = (php_ssh2_sftp_handle_data*)stream->abstract;

	libssh2_sftp_close(data->handle);
	zend_list_delete(data->sftp_rsrcid);
	efree(data);

	return 0;
}
/* }}} */

static php_stream_ops php_ssh2_sftp_dirstream_ops = {
	NULL, /* write */
    php_ssh2_sftp_dirstream_read,
    php_ssh2_sftp_dirstream_close,
    NULL, /* flush */
    PHP_SSH2_SFTP_DIRSTREAM_NAME,
	NULL, /* seek */
    NULL, /* cast */
	NULL, /* fstat */
	NULL, /* set_option */
};

/* {{{ php_ssh2_sftp_dirstream_opener
 */
static php_stream *php_ssh2_sftp_dirstream_opener(	php_stream_wrapper *wrapper, char *filename, char *mode,
													int options, char **opened_path, php_stream_context *context STREAMS_DC TSRMLS_DC)
{
	php_ssh2_sftp_handle_data *data;
	LIBSSH2_SESSION *session = NULL;
	LIBSSH2_SFTP *sftp = NULL;
	LIBSSH2_SFTP_HANDLE *handle;
	php_stream *stream;
	int resource_id = 0, sftp_rsrcid = 0;
	php_url *resource;

	resource = php_ssh2_fopen_wraper_parse_path(filename, "sftp", context, &session, &resource_id, &sftp, &sftp_rsrcid TSRMLS_CC);
	if (!resource || !session || !sftp) {
		return NULL;
	}

	handle = libssh2_sftp_opendir(sftp, resource->path);
	if (!handle) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to open %s on remote host", filename);
		php_url_free(resource);
		zend_list_delete(sftp_rsrcid);
		return NULL;
	}

	data = emalloc(sizeof(php_ssh2_sftp_handle_data));
	data->handle = handle;
	data->sftp_rsrcid = sftp_rsrcid;

	stream = php_stream_alloc(&php_ssh2_sftp_dirstream_ops, data, 0, mode);
	if (!stream) {
		libssh2_sftp_close(handle);
		zend_list_delete(sftp_rsrcid);
		efree(data);
	}
	php_url_free(resource);

	return stream;
}
/* }}} */

/* ****************
   * SFTP Wrapper *
   **************** */

#ifdef ZEND_ENGINE_2
/* {{{ php_ssh2_sftp_urlstat
 */
static int php_ssh2_sftp_urlstat(php_stream_wrapper *wrapper, char *url, int flags, php_stream_statbuf *ssb, php_stream_context *context TSRMLS_DC)
{
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	LIBSSH2_SESSION *session = NULL;
	LIBSSH2_SFTP *sftp = NULL;
	int resource_id = 0, sftp_rsrcid = 0;
	php_url *resource;

	resource = php_ssh2_fopen_wraper_parse_path(url, "sftp", context, &session, &resource_id, &sftp, &sftp_rsrcid TSRMLS_CC);
	if (!resource || !session || !sftp || !resource->path) {
		return -1;
	}

	if (libssh2_sftp_stat_ex(sftp, resource->path, strlen(resource->path),
		(flags & PHP_STREAM_URL_STAT_LINK) ? LIBSSH2_SFTP_LSTAT : LIBSSH2_SFTP_STAT, &attrs)) {
		php_url_free(resource);
		zend_list_delete(sftp_rsrcid);
		return -1;
	}
	
	php_url_free(resource);

	/* parse_path addrefs the resource, but we're not holding on to it so we have to delref it before we leave */
	zend_list_delete(sftp_rsrcid);

	return php_ssh2_sftp_attr2ssb(ssb, &attrs);
}
/* }}} */

/* {{{ php_ssh2_sftp_unlink
 */
static int php_ssh2_sftp_unlink(php_stream_wrapper *wrapper, char *url, int options, php_stream_context *context TSRMLS_DC)
{
	LIBSSH2_SESSION *session = NULL;
	LIBSSH2_SFTP *sftp = NULL;
	int resource_id = 0, sftp_rsrcid = 0;
	php_url *resource;
	int result;

	resource = php_ssh2_fopen_wraper_parse_path(url, "sftp", context, &session, &resource_id, &sftp, &sftp_rsrcid TSRMLS_CC);
	if (!resource || !session || !sftp || !resource->path) {
		if (resource) {
			php_url_free(resource);
		}
		return 0;
	}

	result = libssh2_sftp_unlink(sftp, resource->path);
	php_url_free(resource);

	zend_list_delete(sftp_rsrcid);

	/* libssh2 uses 0 for success and the streams API uses 0 for failure, so invert */
	return (result == 0) ? -1 : 0;
}
/* }}} */

/* {{{ php_ssh2_sftp_rename
 */
static int php_ssh2_sftp_rename(php_stream_wrapper *wrapper, char *url_from, char *url_to, int options, php_stream_context *context TSRMLS_DC)
{
	LIBSSH2_SESSION *session = NULL;
	LIBSSH2_SFTP *sftp = NULL;
	int resource_id = 0, sftp_rsrcid = 0;
	php_url *resource, *resource_to;
	int result;

	if (strncmp(url_from, "ssh2.sftp://", sizeof("ssh2.sftp://") - 1) ||
		strncmp(url_to, "ssh2.sftp://", sizeof("ssh2.sftp://") - 1)) {
		return 0;
	}

	resource_to = php_url_parse(url_to);
	if (!resource_to || !resource_to->path) {
		if (resource_to) {
			php_url_free(resource_to);
		}
		return 0;
	}

	resource = php_ssh2_fopen_wraper_parse_path(url_from, "sftp", context, &session, &resource_id, &sftp, &sftp_rsrcid TSRMLS_CC);
	if (!resource || !session || !sftp || !resource->path) {
		if (resource) {
			php_url_free(resource);
		}
		php_url_free(resource_to);
		return 0;
	}

	result = libssh2_sftp_rename(sftp, resource->path, resource_to->path);
	php_url_free(resource);
	php_url_free(resource_to);

	zend_list_delete(sftp_rsrcid);

	/* libssh2 uses 0 for success and the streams API uses 0 for failure, so invert */
	return (result == 0) ? -1 : 0;
}
/* }}} */

/* {{{ php_ssh2_sftp_mkdir
 */
static int php_ssh2_sftp_mkdir(php_stream_wrapper *wrapper, char *url, int mode, int options, php_stream_context *context TSRMLS_DC)
{
	LIBSSH2_SESSION *session = NULL;
	LIBSSH2_SFTP *sftp = NULL;
	int resource_id = 0, sftp_rsrcid = 0;
	php_url *resource;
	int result;

	resource = php_ssh2_fopen_wraper_parse_path(url, "sftp", context, &session, &resource_id, &sftp, &sftp_rsrcid TSRMLS_CC);
	if (!resource || !session || !sftp || !resource->path) {
		if (resource) {
			php_url_free(resource);
		}
		return 0;
	}

	if (options & PHP_STREAM_MKDIR_RECURSIVE) {
		/* Just attempt to make every directory, some will fail, but we only care about the last success/failure */
		char *p = resource->path;
		while ((p = strchr(p + 1, '/'))) {
			libssh2_sftp_mkdir_ex(sftp, resource->path, p - resource->path, mode);
		}
	}

	result = libssh2_sftp_mkdir(sftp, resource->path, mode);
	php_url_free(resource);

	zend_list_delete(sftp_rsrcid);

	/* libssh2 uses 0 for success and the streams API uses 0 for failure, so invert */
	return (result == 0) ? -1 : 0;
}
/* }}} */

/* {{{ php_ssh2_sftp_rmdir
 */
static int php_ssh2_sftp_rmdir(php_stream_wrapper *wrapper, char *url, int options, php_stream_context *context TSRMLS_DC)
{
	LIBSSH2_SESSION *session = NULL;
	LIBSSH2_SFTP *sftp = NULL;
	int resource_id = 0, sftp_rsrcid = 0;
	php_url *resource;
	int result;

	resource = php_ssh2_fopen_wraper_parse_path(url, "sftp", context, &session, &resource_id, &sftp, &sftp_rsrcid TSRMLS_CC);
	if (!resource || !session || !sftp || !resource->path) {
		if (resource) {
			php_url_free(resource);
		}
		return 0;
	}

	result = libssh2_sftp_rmdir(sftp, resource->path);
	php_url_free(resource);

	zend_list_delete(sftp_rsrcid);

	/* libssh2 uses 0 for success and the streams API uses 0 for failure, so invert */
	return (result == 0) ? -1 : 0;
}
/* }}} */
#endif

static php_stream_wrapper_ops php_ssh2_sftp_wrapper_ops = {
	php_ssh2_sftp_stream_opener,
	NULL, /* close */
	NULL, /* stat */
#ifdef ZEND_ENGINE_2
	php_ssh2_sftp_urlstat,
#else
	NULL, /* url_stat isn't actually functional prior to PHP5 */
#endif
	php_ssh2_sftp_dirstream_opener,
	PHP_SSH2_SFTP_WRAPPER_NAME,
#ifdef ZEND_ENGINE_2
	php_ssh2_sftp_unlink,
	php_ssh2_sftp_rename,
	php_ssh2_sftp_mkdir,
	php_ssh2_sftp_rmdir,
#endif
};

php_stream_wrapper php_ssh2_sftp_wrapper = {
	&php_ssh2_sftp_wrapper_ops,
	NULL,
	1,
#if PHP_MAJOR_VERSION <= 5 && PHP_MINOR_VERSION <= 4
	0,
	NULL,
#endif
};

/* *****************
   * Userspace API *
   ***************** */


/* {{{ proto resource ssh2_sftp(resource session)
 * Request the SFTP subsystem from an already connected SSH2 server
 */
PHP_FUNCTION(ssh2_sftp)
{
	LIBSSH2_SESSION *session;
	LIBSSH2_SFTP *sftp;
	php_ssh2_sftp_data *data;
	zval *zsession;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zsession) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, LIBSSH2_SESSION*, &zsession, -1, PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);

	sftp = libssh2_sftp_init(session);
	if (!sftp) {
		char *sess_err = "Unknown";

		libssh2_session_last_error(session, &sess_err, NULL, 0);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to startup SFTP subsystem: %s", sess_err);
		RETURN_FALSE;
	}

	data = emalloc(sizeof(php_ssh2_sftp_data));
	data->session = session;
	data->sftp = sftp;
	data->session_rsrcid = Z_LVAL_P(zsession);
	zend_list_addref(Z_LVAL_P(zsession));

	ZEND_REGISTER_RESOURCE(return_value, data, le_ssh2_sftp);
}
/* }}} */

/* Much of the stuff below can be done via wrapper ops as of PHP5, but is included here for PHP 4.3 users */

/* {{{ proto bool ssh2_sftp_rename(resource sftp, string from, string to)
 */
PHP_FUNCTION(ssh2_sftp_rename)
{
	php_ssh2_sftp_data *data;
	zval *zsftp;
	char *src, *dst;
	int src_len, dst_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rss", &zsftp, &src, &src_len, &dst, &dst_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(data, php_ssh2_sftp_data*, &zsftp, -1, PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);

	RETURN_BOOL(!libssh2_sftp_rename_ex(data->sftp, src, src_len, dst, dst_len,
				 LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE));
}
/* }}} */

/* {{{ proto bool ssh2_sftp_unlink(resource sftp, string filename)
 */
PHP_FUNCTION(ssh2_sftp_unlink)
{
	php_ssh2_sftp_data *data;
	zval *zsftp;
	char *filename;
	int filename_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zsftp, &filename, &filename_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(data, php_ssh2_sftp_data*, &zsftp, -1, PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);

	RETURN_BOOL(!libssh2_sftp_unlink_ex(data->sftp, filename, filename_len));
}
/* }}} */

/* {{{ proto bool ssh2_sftp_mkdir(resource sftp, string filename[, int mode[, int recursive]])
 */
PHP_FUNCTION(ssh2_sftp_mkdir)
{
	php_ssh2_sftp_data *data;
	zval *zsftp;
	char *filename;
	int filename_len;
	long mode = 0777;
	zend_bool recursive = 0;
	char *p;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|lb", &zsftp, &filename, &filename_len, &mode, &recursive) == FAILURE) {
		return;
	}

	if (filename_len < 1) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(data, php_ssh2_sftp_data*, &zsftp, -1, PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);

	if (recursive) {
		/* Just attempt to make every directory, some will fail, but we only care about the last success/failure */
		p = filename;
		while ((p = strchr(p + 1, '/'))) {
			if ((p - filename) + 1 == filename_len) {
				break;
			}
			libssh2_sftp_mkdir_ex(data->sftp, filename, p - filename, mode);
		}
	}


	RETURN_BOOL(!libssh2_sftp_mkdir_ex(data->sftp, filename, filename_len, mode));
}
/* }}} */

/* {{{ proto bool ssh2_sftp_rmdir(resource sftp, string filename)
 */
PHP_FUNCTION(ssh2_sftp_rmdir)
{
	php_ssh2_sftp_data *data;
	zval *zsftp;
	char *filename;
	int filename_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zsftp, &filename, &filename_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(data, php_ssh2_sftp_data*, &zsftp, -1, PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);

	RETURN_BOOL(!libssh2_sftp_rmdir_ex(data->sftp, filename, filename_len));
}
/* }}} */

/* {{{ proto bool ssh2_sftp_chmod(resource sftp, string filename, int mode)
 */
PHP_FUNCTION(ssh2_sftp_chmod)
{
	php_ssh2_sftp_data *data;
	zval *zsftp;
	char *filename;
	int filename_len;
	long mode;
	LIBSSH2_SFTP_ATTRIBUTES attrs;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsl", &zsftp, &filename, &filename_len, &mode) == FAILURE) {
		return;
	}

	if (filename_len < 1) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(data, php_ssh2_sftp_data*, &zsftp, -1, PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);

	attrs.permissions = mode;
	attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;

	RETURN_BOOL(!libssh2_sftp_stat_ex(data->sftp, filename, filename_len, LIBSSH2_SFTP_SETSTAT, &attrs));
}
/* }}} */

/* {{{ php_ssh2_sftp_stat_func
 * In PHP4.3 this is the only way to request stat into, in PHP >= 5 you can use the fopen wrapper approach
 * Both methods will return identical structures
 * (well, the other one will include other values set to 0 but they don't count)
 */
static void php_ssh2_sftp_stat_func(INTERNAL_FUNCTION_PARAMETERS, int stat_type)
{
	php_ssh2_sftp_data *data;
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	zval *zsftp;
	char *path;
	int path_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zsftp, &path, &path_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(data, php_ssh2_sftp_data*, &zsftp, -1, PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);

	if (libssh2_sftp_stat_ex(data->sftp, path, path_len, stat_type, &attrs)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to stat remote file");
		RETURN_FALSE;
	}

	array_init(return_value);

	if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
		add_index_long(return_value, 7, attrs.filesize);
		add_assoc_long(return_value, "size", attrs.filesize);
	}
	if (attrs.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
		add_index_long(return_value, 4, attrs.uid);
		add_assoc_long(return_value, "uid", attrs.uid);

		add_index_long(return_value, 5, attrs.gid);
		add_assoc_long(return_value, "gid", attrs.gid);
	}
	if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
		add_index_long(return_value, 2, attrs.permissions);
		add_assoc_long(return_value, "mode", attrs.permissions);
	}
	if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
		add_index_long(return_value, 8, attrs.atime);
		add_assoc_long(return_value, "atime", attrs.atime);

		add_index_long(return_value, 9, attrs.mtime);
		add_assoc_long(return_value, "mtime", attrs.mtime);
	}
}
/* }}} */

/* {{{ proto array ssh2_sftp_stat(resource sftp, string path)
 */
PHP_FUNCTION(ssh2_sftp_stat)
{
	php_ssh2_sftp_stat_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, LIBSSH2_SFTP_STAT);
}
/* }}} */

/* {{{ proto array ssh2_sftp_lstat(resource sftp, string path)
 */
PHP_FUNCTION(ssh2_sftp_lstat)
{
	php_ssh2_sftp_stat_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, LIBSSH2_SFTP_LSTAT);
}
/* }}} */

/* {{{ proto bool ssh2_sftp_symlink(resource sftp, string target, string link)
 */
PHP_FUNCTION(ssh2_sftp_symlink)
{
	php_ssh2_sftp_data *data;
	zval *zsftp;
	char *targ, *link;
	int targ_len, link_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rss", &zsftp, &targ, &targ_len, &link, &link_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(data, php_ssh2_sftp_data*, &zsftp, -1, PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);

	RETURN_BOOL(!libssh2_sftp_symlink_ex(data->sftp, targ, targ_len, link, link_len, LIBSSH2_SFTP_SYMLINK));
}
/* }}} */

/* {{{ proto string ssh2_sftp_readlink(resource sftp, string link)
 */
PHP_FUNCTION(ssh2_sftp_readlink)
{
	php_ssh2_sftp_data *data;
	zval *zsftp;
	char *link;
	int targ_len = 0, link_len;
	char targ[8192];

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zsftp, &link, &link_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(data, php_ssh2_sftp_data*, &zsftp, -1, PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);

	if ((targ_len = libssh2_sftp_symlink_ex(data->sftp, link, link_len, targ, 8192, LIBSSH2_SFTP_READLINK)) < 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to read link '%s'", link);
		RETURN_FALSE;
	}

	RETURN_STRINGL(targ, targ_len, 1);
}
/* }}} */

/* {{{ proto string ssh2_sftp_realpath(resource sftp, string filename)
 */
PHP_FUNCTION(ssh2_sftp_realpath)
{
	php_ssh2_sftp_data *data;
	zval *zsftp;
	char *link;
	int targ_len = 0, link_len;
	char targ[8192];

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zsftp, &link, &link_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(data, php_ssh2_sftp_data*, &zsftp, -1, PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);

	if ((targ_len = libssh2_sftp_symlink_ex(data->sftp, link, link_len, targ, 8192, LIBSSH2_SFTP_REALPATH)) < 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to resolve realpath for '%s'", link);
		RETURN_FALSE;
	}

	RETURN_STRINGL(targ, targ_len, 1);
}
/* }}} */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * End:
 */

