/*
  +----------------------------------------------------------------------+
  | PHP Version 4                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2003 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.02 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available at through the world-wide-web at                           |
  | http://www.php.net/license/2_02.txt.                                 |
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
#include "ext/standard/info.h"
#include "php_ssh2.h"
#include "main/php_network.h"

/* Internal Constants */
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH	20
#endif

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH	16
#endif

/* True global resources - no need for thread safety here */
int le_ssh2_session;
int le_ssh2_sftp;

/* *************
   * Callbacks *
   ************* */

#ifdef ZTS
#define PHP_SSH2_TSRMLS_FETCH()		TSRMLS_D = *(void****)abstract;
#else
#define PHP_SSH2_TSRMLS_FETCH()
#endif

/* {{{ php_ssh2_alloc_cb
 * Wrap emalloc()
 */
static LIBSSH2_ALLOC_FUNC(php_ssh2_alloc_cb)
{
	return emalloc(count);
}
/* }}} */

/* {{{ php_ssh2_free_cb
 * Wrap efree()
 */
static LIBSSH2_FREE_FUNC(php_ssh2_free_cb)
{
	efree(ptr);
}
/* }}} */

/* {{{ php_ssh2_realloc_cb
 * Wrap erealloc()
 */
static LIBSSH2_REALLOC_FUNC(php_ssh2_realloc_cb)
{
	return erealloc(ptr, count);
}
/* }}} */

/* {{{ php_ssh2_debug_cb
 * Debug packets
 */
LIBSSH2_DEBUG_FUNC(php_ssh2_debug_cb)
{
	php_ssh2_session_data *data;
	zval *zdisplay, *zmessage, *zlanguage;
	zval **args[3];
	SSH2_TSRMLS_FETCH(*abstract);

	if (!abstract || !*abstract) {
		return;
	}
	data = (php_ssh2_session_data*)*abstract;
	if (!data->debug_cb) {
		return;
	}

	MAKE_STD_ZVAL(zmessage);
	ZVAL_STRINGL(zmessage, (char*)message, message_len, 1);
	args[0] = &zmessage;

	MAKE_STD_ZVAL(zlanguage);
	ZVAL_STRINGL(zlanguage, (char*)language, language_len, 1);
	args[1] = &zlanguage;

	MAKE_STD_ZVAL(zdisplay);
	ZVAL_LONG(zdisplay, always_display);
	args[2] = &zdisplay;

	if (FAILURE == call_user_function_ex(NULL, NULL, data->disconnect_cb, NULL, 3, args, 0, NULL TSRMLS_CC)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failure calling disconnect callback");
	}
	zval_ptr_dtor(&zdisplay);
	zval_ptr_dtor(&zmessage);
	zval_ptr_dtor(&zlanguage);
}
/* }}} */

/* {{{ php_ssh2_ignore_cb
 * Ignore packets
 */
LIBSSH2_IGNORE_FUNC(php_ssh2_ignore_cb)
{
	php_ssh2_session_data *data;
	zval *zretval = NULL, *zmessage;
	zval **args[1];
	SSH2_TSRMLS_FETCH(*abstract);

	if (!abstract || !*abstract) {
		return;
	}
	data = (php_ssh2_session_data*)*abstract;
	if (!data->ignore_cb) {
		return;
	}

	MAKE_STD_ZVAL(zmessage);
	ZVAL_STRINGL(zmessage, (char*)message, message_len, 1);
	args[0] = &zmessage;

	if (FAILURE == call_user_function_ex(NULL, NULL, data->ignore_cb, &zretval, 1, args, 0, NULL TSRMLS_CC)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failure calling ignore callback");
	}
	zval_ptr_dtor(&zmessage);
	if (zretval) {
		zval_ptr_dtor(&zretval);
	}
}
/* }}} */

/* {{{ php_ssh2_macerror_cb
 * Called when a MAC error occurs, offers the chance to ignore
 * WHY ARE YOU IGNORING MAC ERRORS??????
 */
LIBSSH2_MACERROR_FUNC(php_ssh2_macerror_cb)
{
	php_ssh2_session_data *data;
	zval *zretval = NULL, *zpacket;
	zval **args[1];
	int retval = -1;
	SSH2_TSRMLS_FETCH(*abstract);

	if (!abstract || !*abstract) {
		return -1;
	}
	data = (php_ssh2_session_data*)*abstract;
	if (!data->macerror_cb) {
		return -1;
	}

	MAKE_STD_ZVAL(zpacket);
	ZVAL_STRINGL(zpacket, (char*)packet, packet_len, 1);
	args[0] = &zpacket;

	if (FAILURE == call_user_function_ex(NULL, NULL, data->macerror_cb, &zretval, 1, args, 0, NULL TSRMLS_CC)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failure calling macerror callback");
	} else {
		retval = zval_is_true(zretval) ? 0 : -1;
	}
	zval_ptr_dtor(&zpacket);
	if (zretval) {
		zval_ptr_dtor(&zretval);
	}

	return retval;
}
/* }}} */

/* {{{ php_ssh2_disconnect_cb
 * Connection closed by foreign host
 */
LIBSSH2_DISCONNECT_FUNC(php_ssh2_disconnect_cb)
{
	php_ssh2_session_data *data;
	zval *zreason, *zmessage, *zlanguage;
	zval **args[3];
	SSH2_TSRMLS_FETCH(*abstract);

	if (!abstract || !*abstract) {
		return;
	}
	data = (php_ssh2_session_data*)*abstract;
	if (!data->disconnect_cb) {
		return;
	}

	MAKE_STD_ZVAL(zreason);
	ZVAL_LONG(zreason, reason);
	args[0] = &zreason;

	MAKE_STD_ZVAL(zmessage);
	ZVAL_STRINGL(zmessage, (char*)message, message_len, 1);
	args[1] = &zmessage;

	MAKE_STD_ZVAL(zlanguage);
	ZVAL_STRINGL(zlanguage, (char*)language, language_len, 1);
	args[2] = &zlanguage;

	if (FAILURE == call_user_function_ex(NULL, NULL, data->disconnect_cb, NULL, 3, args, 0, NULL TSRMLS_CC)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failure calling disconnect callback");
	}
	zval_ptr_dtor(&zreason);
	zval_ptr_dtor(&zmessage);
	zval_ptr_dtor(&zlanguage);
}
/* }}} */

/* *****************
   * Userspace API *
   ***************** */

/* {{{ php_ssh2_set_callback
 * Try to set a method if it's passed in with the hash table
 */
static int php_ssh2_set_callback(LIBSSH2_SESSION *session, HashTable *ht, char *callback, int callback_len, int callback_type, php_ssh2_session_data *data)
{
	zval **handler, *copyval;
	void *internal_handler;

	if (zend_hash_find(ht, callback, callback_len + 1, (void**)&handler) == FAILURE) {
		return 0;
	}

	if (!handler || !*handler || !zend_is_callable(*handler, 0, NULL)) {
		return -1;
	}

	ALLOC_INIT_ZVAL(copyval);
	*copyval = **handler;
	zval_copy_ctor(copyval);

	switch (callback_type) {
		case LIBSSH2_CALLBACK_IGNORE:
			internal_handler = php_ssh2_ignore_cb;
			if (data->ignore_cb) {
				zval_ptr_dtor(&data->ignore_cb);
			}
			data->ignore_cb = copyval;
			break;
		case LIBSSH2_CALLBACK_DEBUG:
			internal_handler = php_ssh2_debug_cb;
			if (data->debug_cb) {
				zval_ptr_dtor(&data->debug_cb);
			}
			data->debug_cb = copyval;
			break;
		case LIBSSH2_CALLBACK_MACERROR:
			internal_handler = php_ssh2_macerror_cb;
			if (data->macerror_cb) {
				zval_ptr_dtor(&data->macerror_cb);
			}
			data->macerror_cb = copyval;
			break;
		case LIBSSH2_CALLBACK_DISCONNECT:
			internal_handler = php_ssh2_disconnect_cb;
			if (data->disconnect_cb) {
				zval_ptr_dtor(&data->disconnect_cb);
			}
			data->disconnect_cb = copyval;
			break;
		default:
			zval_ptr_dtor(&copyval);
			return -1;
	}

	libssh2_session_callback_set(session, callback_type, internal_handler);

	return 0;
}
/* }}} */

/* {{{ php_ssh2_set_method
 * Try to set a method if it's passed in with the hash table
 */
static int php_ssh2_set_method(LIBSSH2_SESSION *session, HashTable *ht, char *method, int method_len, int method_type)
{
	zval **value;

	if (zend_hash_find(ht, method, method_len + 1, (void**)&value) == FAILURE) {
		return 0;
	}

	if (!value || !*value || (Z_TYPE_PP(value) != IS_STRING)) {
		return -1;
	}

	return libssh2_session_method_pref(session, method_type, Z_STRVAL_PP(value));
}
/* }}} */

/* {{{ php_ssh2_session_connect
 * Connect to an SSH server with requested methods
 */
LIBSSH2_SESSION *php_ssh2_session_connect(char *host, int port, zval *methods, zval *callbacks TSRMLS_DC)
{
	LIBSSH2_SESSION *session;
	int socket;
	php_ssh2_session_data *data;

#ifdef ZEND_ENGINE_2
	socket = php_network_connect_socket_to_host(host, port, SOCK_STREAM, 0, NULL, NULL, NULL TSRMLS_CC);
#else
	socket = php_hostconnect(host, port, SOCK_STREAM, NULL TSRMLS_CC);
#endif

	if (socket <= 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to connect to %s on port %d", host, port);
		return NULL;
	}

	data = ecalloc(1, sizeof(php_ssh2_session_data));
	SSH2_TSRMLS_SET(data);

	session = libssh2_session_init_ex(php_ssh2_alloc_cb, php_ssh2_free_cb, php_ssh2_realloc_cb, data);
	if (!session) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to initialize SSH2 session");
		efree(data);
		close(socket);
		return NULL;
	}
	libssh2_banner_set(session, LIBSSH2_SSH_DEFAULT_BANNER " PHP");

	/* Override method preferences */
	if (methods) {
		zval **container;

		if (php_ssh2_set_method(session, HASH_OF(methods), "kex", sizeof("kex") - 1, LIBSSH2_METHOD_KEX)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding KEX method");
		}
		if (php_ssh2_set_method(session, HASH_OF(methods), "hostkey", sizeof("hostkey") - 1, LIBSSH2_METHOD_HOSTKEY)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding HOSTKEY method");
		}

		if (zend_hash_find(HASH_OF(methods), "client_to_server", sizeof("client_to_server"), (void**)&container) == SUCCESS &&
			container && *container && Z_TYPE_PP(container) == IS_ARRAY) {
			if (php_ssh2_set_method(session, HASH_OF(*container), "crypt", sizeof("crypt") - 1, LIBSSH2_METHOD_CRYPT_CS)) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding client to server CRYPT method");
			}
			if (php_ssh2_set_method(session, HASH_OF(*container), "mac", sizeof("mac") - 1, LIBSSH2_METHOD_MAC_CS)) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding client to server MAC method");
			}
			if (php_ssh2_set_method(session, HASH_OF(*container), "comp", sizeof("comp") - 1, LIBSSH2_METHOD_COMP_CS)) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding client to server COMP method");
			}
			if (php_ssh2_set_method(session, HASH_OF(*container), "lang", sizeof("lang") - 1, LIBSSH2_METHOD_LANG_CS)) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding client to server LANG method");
			}
		}

		if (zend_hash_find(HASH_OF(methods), "server_to_client", sizeof("server_to_client"), (void**)&container) == SUCCESS &&
			container && *container && Z_TYPE_PP(container) == IS_ARRAY) {
			if (php_ssh2_set_method(session, HASH_OF(*container), "crypt", sizeof("crypt") - 1, LIBSSH2_METHOD_CRYPT_SC)) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding server to client CRYPT method");
			}
			if (php_ssh2_set_method(session, HASH_OF(*container), "mac", sizeof("mac") - 1, LIBSSH2_METHOD_MAC_SC)) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding server to client MAC method");
			}
			if (php_ssh2_set_method(session, HASH_OF(*container), "comp", sizeof("comp") - 1, LIBSSH2_METHOD_COMP_SC)) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding server to client COMP method");
			}
			if (php_ssh2_set_method(session, HASH_OF(*container), "lang", sizeof("lang") - 1, LIBSSH2_METHOD_LANG_SC)) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed overriding server to client LANG method");
			}
		}
	}

	/* Register Callbacks */
	if (callbacks) {
		/* ignore debug disconnect macerror */

		if (php_ssh2_set_callback(session, HASH_OF(callbacks), "ignore", sizeof("ignore") - 1, LIBSSH2_CALLBACK_IGNORE, data)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed setting IGNORE callback");
		}

		if (php_ssh2_set_callback(session, HASH_OF(callbacks), "debug", sizeof("debug") - 1, LIBSSH2_CALLBACK_DEBUG, data)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed setting DEBUG callback");
		}

		if (php_ssh2_set_callback(session, HASH_OF(callbacks), "macerror", sizeof("macerror") - 1, LIBSSH2_CALLBACK_MACERROR, data)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed setting MACERROR callback");
		}

		if (php_ssh2_set_callback(session, HASH_OF(callbacks), "disconnect", sizeof("disconnect") - 1, LIBSSH2_CALLBACK_DISCONNECT, data)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed setting DISCONNECT callback");
		}
	}

	if (libssh2_session_startup(session, socket)) {
		close(socket);
		libssh2_session_free(session);
		return NULL;
	}

	return session;
}
/* }}} */

/* {{{ proto resource ssh2_connect(string host[, int port[, array methods[, array callbacks]]])
 * Establish a connection to a remote SSH server and return a resource on success, false on error
 */
PHP_FUNCTION(ssh2_connect)
{
	LIBSSH2_SESSION *session;
	zval *methods = NULL, *callbacks = NULL;
	char *host;
	long port = PHP_SSH2_DEFAULT_PORT;
	int host_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|la!a!", &host, &host_len, &port, &methods, &callbacks) == FAILURE) {
		RETURN_FALSE;
	}

	session = php_ssh2_session_connect(host, port, methods, callbacks TSRMLS_CC);
	if (!session) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to connect to %s", host);
		RETURN_FALSE;
	}

	ZEND_REGISTER_RESOURCE(return_value, session, le_ssh2_session);
}
/* }}} */

/* {{{ proto array ssh2_methods_negotiated(resource session)
 * Return list of negotiaed methods
 */
PHP_FUNCTION(ssh2_methods_negotiated)
{
	LIBSSH2_SESSION *session;
	zval *zsession, *endpoint;
	char *kex, *hostkey, *crypt_cs, *crypt_sc, *mac_cs, *mac_sc, *comp_cs, *comp_sc, *lang_cs, *lang_sc;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zsession) == FAILURE) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(session, LIBSSH2_SESSION*, &zsession, -1, PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);

	libssh2_session_methods(session, &kex, &hostkey, &crypt_cs, &crypt_sc, &mac_cs, &mac_sc, &comp_cs, &comp_sc, &lang_cs, &lang_sc);

	array_init(return_value);
	add_assoc_string(return_value, "kex", kex, 1);
	add_assoc_string(return_value, "hostkey", hostkey, 1);

	ALLOC_INIT_ZVAL(endpoint);
	array_init(endpoint);
	add_assoc_string(endpoint, "crypt", crypt_cs, 1);
	add_assoc_string(endpoint, "mac", mac_cs, 1);
	add_assoc_string(endpoint, "comp", comp_cs, 1);
	add_assoc_string(endpoint, "lang", lang_cs, 1);
	add_assoc_zval(return_value, "client_to_server", endpoint);

	ALLOC_INIT_ZVAL(endpoint);
	array_init(endpoint);
	add_assoc_string(endpoint, "crypt", crypt_sc, 1);
	add_assoc_string(endpoint, "mac", mac_sc, 1);
	add_assoc_string(endpoint, "comp", comp_sc, 1);
	add_assoc_string(endpoint, "lang", lang_sc, 1);
	add_assoc_zval(return_value, "server_to_client", endpoint);
}
/* }}} */

/* {{{ proto string ssh2_fingerprint(resource session[, int flags])
 * Returns a server hostkey hash from an active session
 * Defaults to MD5 fingerprint encoded as ASCII hex values
 */
PHP_FUNCTION(ssh2_fingerprint)
{
	LIBSSH2_SESSION *session;
	zval *zsession;
	char *fingerprint;
	long flags = 0;
	int i, fingerprint_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r|l", &zsession, &flags) == FAILURE) {
		RETURN_FALSE;
	}
	fingerprint_len = (flags & PHP_SSH2_FINGERPRINT_SHA1) ? SHA_DIGEST_LENGTH : MD5_DIGEST_LENGTH;

	ZEND_FETCH_RESOURCE(session, LIBSSH2_SESSION*, &zsession, -1, PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);

	fingerprint = libssh2_hostkey_hash(session, (flags & PHP_SSH2_FINGERPRINT_SHA1) ? LIBSSH2_HOSTKEY_HASH_SHA1 : LIBSSH2_HOSTKEY_HASH_MD5);
	if (!fingerprint) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to retreive fingerprint from specified session");
		RETURN_FALSE;
	}

	for(i = 0; i < fingerprint_len; i++) {
		if (fingerprint[i] != '\0') {
			goto fingerprint_good;
		}
	}
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "No fingerprint available using specified hash");
	RETURN_NULL();
 fingerprint_good:
	if (flags & PHP_SSH2_FINGERPRINT_RAW) {
		RETURN_STRINGL(fingerprint, fingerprint_len, 1);
	} else {
		char *hexchars;

		hexchars = emalloc((fingerprint_len * 2) + 1);
		for(i = 0; i < fingerprint_len; i++) {
			snprintf(hexchars + (2 * i), 3, "%02X", (unsigned char)fingerprint[i]);
		}
		RETURN_STRINGL(hexchars, 2 * fingerprint_len, 0);
	}
}
/* }}} */

/* {{{ proto array ssh2_auth_none(resource session, string username)
 * Attempt "none" authentication, returns a list of allowed methods on failed authentication, 
 * false on utter failure, or true on success
 */
PHP_FUNCTION(ssh2_auth_none)
{
	LIBSSH2_SESSION *session;
	zval *zsession;
	char *username, *methods, *s, *p;
	int username_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zsession, &username, &username_len) == FAILURE) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(session, LIBSSH2_SESSION*, &zsession, -1, PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);

	s = methods = libssh2_userauth_list(session, username, username_len);
	if (!methods) {
		/* Either bad failure, or unexpected success */
		RETURN_BOOL(libssh2_userauth_authenticated(session));
	}

	array_init(return_value);
	while ((p = strchr(s, ','))) {
		if ((p - s) > 0) {
			add_next_index_stringl(return_value, s, p - s, 1);
		}
		s = p + 1;
	}
	if (strlen(s)) {
		add_next_index_string(return_value, s, 1);
	}
	efree(methods);
}
/* }}} */

/* {{{ proto bool ssh2_auth_password(resource session, string username, string password)
 * Authenticate over SSH using a plain password
 */
PHP_FUNCTION(ssh2_auth_password)
{
	LIBSSH2_SESSION *session;
	zval *zsession;
	char *username, *password;
	int username_len, password_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rss", &zsession, &username, &username_len, &password, &password_len) == FAILURE) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(session, LIBSSH2_SESSION*, &zsession, -1, PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);

	/* TODO: Support password change callback */
	if (libssh2_userauth_password_ex(session, username, username_len, password, password_len, NULL)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Authentication failed for %s using password", username);
		RETURN_FALSE;
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool ssh2_auth_pubkey_file(resource session, string username, string pubkeyfile, string privkeyfile[, string passphrase])
 * Authenticate using a public key
 */
PHP_FUNCTION(ssh2_auth_pubkey_file)
{
	LIBSSH2_SESSION *session;
	zval *zsession;
	char *username, *pubkey, *privkey, *passphrase = NULL;
	int username_len, pubkey_len, privkey_len, passphrase_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsss|s", &zsession,	&username, &username_len,
																				&pubkey, &pubkey_len,
																				&privkey, &privkey_len,
																				&passphrase, &passphrase_len) == FAILURE) {
		RETURN_FALSE;
	}

	if (PG(safe_mode) && !php_checkuid(pubkey, NULL, CHECKUID_CHECK_FILE_AND_DIR)) {
		RETURN_FALSE;
	}
	if (PG(safe_mode) && !php_checkuid(privkey, NULL, CHECKUID_CHECK_FILE_AND_DIR)) {
		RETURN_FALSE;
	}

	if (php_check_open_basedir(pubkey TSRMLS_CC)) {
		RETURN_FALSE;
	}
	if (php_check_open_basedir(privkey TSRMLS_CC)) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(session, LIBSSH2_SESSION*, &zsession, -1, PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);

	/* TODO: Support passphrase callback */
	if (libssh2_userauth_publickey_fromfile_ex(session, username, username_len, pubkey, privkey, passphrase)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Authentication failed for %s using public key", username);
		RETURN_FALSE;
	}

	RETURN_TRUE;
}
/* }}} */

/* ***********************
   * Module Housekeeping *
   *********************** */

static void php_ssh2_session_dtor(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	LIBSSH2_SESSION *session = (LIBSSH2_SESSION*)rsrc->ptr;
	php_ssh2_session_data **data = (php_ssh2_session_data**)libssh2_session_abstract(session);

	if (*data) {
		if ((*data)->ignore_cb) {
			zval_ptr_dtor(&(*data)->ignore_cb);
		}
		if ((*data)->debug_cb) {
			zval_ptr_dtor(&(*data)->debug_cb);
		}
		if ((*data)->macerror_cb) {
			zval_ptr_dtor(&(*data)->macerror_cb);
		}
		if ((*data)->disconnect_cb) {
			zval_ptr_dtor(&(*data)->disconnect_cb);
		}

		efree(*data);
		*data = NULL;
	}

	libssh2_session_free(session);
}

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(ssh2)
{
	le_ssh2_session	= zend_register_list_destructors_ex(php_ssh2_session_dtor, NULL, PHP_SSH2_SESSION_RES_NAME, module_number);
	le_ssh2_sftp	= zend_register_list_destructors_ex(php_ssh2_sftp_dtor, NULL, PHP_SSH2_SFTP_RES_NAME, module_number);

	REGISTER_LONG_CONSTANT("SSH2_FINGERPRINT_MD5",		PHP_SSH2_FINGERPRINT_MD5,		CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_FINGERPRINT_SHA1",		PHP_SSH2_FINGERPRINT_SHA1,		CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_FINGERPRINT_HEX",		PHP_SSH2_FINGERPRINT_HEX,		CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_FINGERPRINT_RAW",		PHP_SSH2_FINGERPRINT_RAW,		CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("SSH2_TERM_UNIT_CHARS",		PHP_SSH2_TERM_UNIT_CHARS,		CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_TERM_UNIT_PIXELS",		PHP_SSH2_TERM_UNIT_PIXELS,		CONST_CS | CONST_PERSISTENT);

	REGISTER_STRING_CONSTANT("SSH2_DEFAULT_TERMINAL",	PHP_SSH2_DEFAULT_TERMINAL,		CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_DEFAULT_TERM_WIDTH",	PHP_SSH2_DEFAULT_TERM_WIDTH,	CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_DEFAULT_TERM_HEIGHT",	PHP_SSH2_DEFAULT_TERM_HEIGHT,	CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_DEFAULT_TERM_UNIT",	PHP_SSH2_DEFAULT_TERM_UNIT,		CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("SSH2_STREAM_STDIO",			0,								CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_STREAM_STDERR",		SSH_EXTENDED_DATA_STDERR,		CONST_CS | CONST_PERSISTENT);

	return (php_register_url_stream_wrapper("ssh2.shell", &php_ssh2_stream_wrapper_shell TSRMLS_CC) == SUCCESS &&
			php_register_url_stream_wrapper("ssh2.exec", &php_ssh2_stream_wrapper_exec TSRMLS_CC) == SUCCESS &&
			php_register_url_stream_wrapper("ssh2.tunnel", &php_ssh2_stream_wrapper_tunnel TSRMLS_CC) == SUCCESS &&
			php_register_url_stream_wrapper("ssh2.scp", &php_ssh2_stream_wrapper_scp TSRMLS_CC) == SUCCESS &&
			php_register_url_stream_wrapper("ssh2.sftp", &php_ssh2_sftp_wrapper TSRMLS_CC) == SUCCESS) ? SUCCESS : FAILURE;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(ssh2)
{
	return (php_unregister_url_stream_wrapper("ssh2.shell" TSRMLS_CC) == SUCCESS &&
			php_unregister_url_stream_wrapper("ssh2.exec" TSRMLS_CC) == SUCCESS &&
			php_unregister_url_stream_wrapper("ssh2.tunnel" TSRMLS_CC) == SUCCESS &&
			php_unregister_url_stream_wrapper("ssh2.scp" TSRMLS_CC) == SUCCESS &&
			php_unregister_url_stream_wrapper("ssh2.sftp" TSRMLS_CC) == SUCCESS) ? SUCCESS : FAILURE;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(ssh2)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "ssh2 support", "enabled");
	php_info_print_table_end();
}
/* }}} */

/* {{{ ssh2_functions[]
 */
function_entry ssh2_functions[] = {
	PHP_FE(ssh2_connect,						NULL)
	PHP_FE(ssh2_methods_negotiated,				NULL)
	PHP_FE(ssh2_fingerprint,					NULL)

	PHP_FE(ssh2_auth_none,						NULL)
	PHP_FE(ssh2_auth_password,					NULL)
	PHP_FE(ssh2_auth_pubkey_file,				NULL)

	/* Stream Stuff */
	PHP_FE(ssh2_shell,							NULL)
	PHP_FE(ssh2_exec,							NULL)
	PHP_FE(ssh2_tunnel,							NULL)
	PHP_FE(ssh2_scp_recv,						NULL)
	PHP_FE(ssh2_scp_send,						NULL)
	PHP_FE(ssh2_fetch_stream,					NULL)

	/* SFTP Stuff */
	PHP_FE(ssh2_sftp,							NULL)

	/* SFTP Wrapper Ops */
	PHP_FE(ssh2_sftp_rename,					NULL)
	PHP_FE(ssh2_sftp_unlink,					NULL)
	PHP_FE(ssh2_sftp_mkdir,						NULL)
	PHP_FE(ssh2_sftp_rmdir,						NULL)
	PHP_FE(ssh2_sftp_stat,						NULL)
	PHP_FE(ssh2_sftp_lstat,						NULL)
	PHP_FE(ssh2_sftp_symlink,					NULL)
	PHP_FE(ssh2_sftp_readlink,					NULL)
	PHP_FE(ssh2_sftp_realpath,					NULL)

	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ ssh2_module_entry
 */
zend_module_entry ssh2_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"ssh2",
	ssh2_functions,
	PHP_MINIT(ssh2),
	PHP_MSHUTDOWN(ssh2),
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	PHP_MINFO(ssh2),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_SSH2_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_SSH2
ZEND_GET_MODULE(ssh2)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
