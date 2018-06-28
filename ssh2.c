/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2016 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Sara Golemon <pollita@php.net>                               |
   +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/file.h"
#include "php_ssh2.h"
#include "main/php_network.h"

#if (OPENSSL_VERSION_NUMBER >= 0x00908000L)
#include <openssl/applink.c>
#endif

/* Internal Constants */
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH	20
#endif

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH	16
#endif

/* True global resources - no need for thread safety here */
int le_ssh2_session;
int le_ssh2_listener;
int le_ssh2_sftp;
int le_ssh2_pkey_subsys;

ZEND_BEGIN_ARG_INFO(php_ssh2_first_arg_force_ref, 0)
	ZEND_ARG_PASS_INFO(1)
ZEND_END_ARG_INFO()

/* *************
   * Callbacks *
   ************* */

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
	zval args[3];

	if (!abstract || !*abstract) {
		return;
	}
	data = (php_ssh2_session_data*)*abstract;
	if (!data->debug_cb) {
		return;
	}

	ZVAL_STRINGL(&args[0], message, message_len);
	ZVAL_STRINGL(&args[1], language, language_len);
	ZVAL_LONG(&args[2], always_display);

	if (FAILURE == call_user_function_ex(NULL, NULL, data->disconnect_cb, NULL, 3, args, 0, NULL)) {
		php_error_docref(NULL, E_WARNING, "Failure calling disconnect callback");
	}
}
/* }}} */

/* {{{ php_ssh2_ignore_cb
 * Ignore packets
 */
LIBSSH2_IGNORE_FUNC(php_ssh2_ignore_cb)
{
	php_ssh2_session_data *data;
	zval zretval;
	zval args[1];

	if (!abstract || !*abstract) {
		return;
	}
	data = (php_ssh2_session_data*)*abstract;
	if (!data->ignore_cb) {
		return;
	}

	ZVAL_STRINGL(&args[0], message, message_len);

	if (FAILURE == call_user_function_ex(NULL, NULL, data->ignore_cb, &zretval, 1, args, 0, NULL)) {
		php_error_docref(NULL, E_WARNING, "Failure calling ignore callback");
	}
	if (Z_TYPE_P(&zretval) != IS_UNDEF) {
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
	zval zretval;
	zval args[1];
	int retval = -1;

	if (!abstract || !*abstract) {
		return -1;
	}
	data = (php_ssh2_session_data*)*abstract;
	if (!data->macerror_cb) {
		return -1;
	}

	ZVAL_STRINGL(&args[0], packet, packet_len);

	if (FAILURE == call_user_function_ex(NULL, NULL, data->macerror_cb, &zretval, 1, args, 0, NULL)) {
		php_error_docref(NULL, E_WARNING, "Failure calling macerror callback");
	} else {
		retval = zval_is_true(&zretval) ? 0 : -1;
	}
	if (Z_TYPE_P(&zretval) != IS_UNDEF) {
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
	zval args[3];

	if (!abstract || !*abstract) {
		return;
	}
	data = (php_ssh2_session_data*)*abstract;
	if (!data->disconnect_cb) {
		return;
	}

	ZVAL_LONG(&args[0], reason);
	ZVAL_STRINGL(&args[1], message, message_len);
	ZVAL_STRINGL(&args[2], language, language_len);

	if (FAILURE == call_user_function_ex(NULL, NULL, data->disconnect_cb, NULL, 3, args, 0, NULL)) {
		php_error_docref(NULL, E_WARNING, "Failure calling disconnect callback");
	}
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
	zval *handler, *copyval;
	void *internal_handler;
	zend_string *callback_zstring;

	callback_zstring = zend_string_init(callback, callback_len, 0);
	if ((handler = zend_hash_find(ht, callback_zstring)) == NULL) {
			zend_string_release(callback_zstring);
		return 0;
	}
	zend_string_release(callback_zstring);

	if (!zend_is_callable(handler, 0, NULL)) {
		return -1;
	}

	copyval = handler;
	zval_copy_ctor(copyval);

	switch (callback_type) {
		case LIBSSH2_CALLBACK_IGNORE:
			internal_handler = php_ssh2_ignore_cb;
			if (data->ignore_cb) {
				zval_ptr_dtor(data->ignore_cb);
			}
			data->ignore_cb = copyval;
			break;
		case LIBSSH2_CALLBACK_DEBUG:
			internal_handler = php_ssh2_debug_cb;
			if (data->debug_cb) {
				zval_ptr_dtor(data->debug_cb);
			}
			data->debug_cb = copyval;
			break;
		case LIBSSH2_CALLBACK_MACERROR:
			internal_handler = php_ssh2_macerror_cb;
			if (data->macerror_cb) {
				zval_ptr_dtor(data->macerror_cb);
			}
			data->macerror_cb = copyval;
			break;
		case LIBSSH2_CALLBACK_DISCONNECT:
			internal_handler = php_ssh2_disconnect_cb;
			if (data->disconnect_cb) {
				zval_ptr_dtor(data->disconnect_cb);
			}
			data->disconnect_cb = copyval;
			break;
		default:
			zval_ptr_dtor(copyval);
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
	zval *value;
	zend_string *method_zstring;


	method_zstring = zend_string_init(method, method_len, 0);
	if ((value = zend_hash_find(ht, method_zstring)) == NULL) {
		zend_string_release(method_zstring);
		return 0;
	}
	zend_string_release(method_zstring);

	if ((Z_TYPE_P(value) != IS_STRING)) {
		return -1;
	}

	return libssh2_session_method_pref(session, method_type, Z_STRVAL_P(value));
}
/* }}} */

/* {{{ php_ssh2_session_connect
 * Connect to an SSH server with requested methods
 */
LIBSSH2_SESSION *php_ssh2_session_connect(char *host, int port, zval *methods, zval *callbacks)
{
	LIBSSH2_SESSION *session;
	int socket;
	php_ssh2_session_data *data;
	struct timeval tv;
	zend_string *hash_lookup_zstring;

	tv.tv_sec = FG(default_socket_timeout);
	tv.tv_usec = 0;

	socket = php_network_connect_socket_to_host(host, port, SOCK_STREAM, 0, &tv, NULL, NULL, NULL, 0, STREAM_SOCKOP_NONE);

	if (socket <= 0) {
		php_error_docref(NULL, E_WARNING, "Unable to connect to %s on port %d", host, port);
		return NULL;
	}

	data = ecalloc(1, sizeof(php_ssh2_session_data));
	data->socket = socket;

	session = libssh2_session_init_ex(php_ssh2_alloc_cb, php_ssh2_free_cb, php_ssh2_realloc_cb, data);
	if (!session) {
		php_error_docref(NULL, E_WARNING, "Unable to initialize SSH2 session");
		efree(data);
		closesocket(socket);
		return NULL;
	}
	libssh2_banner_set(session, LIBSSH2_SSH_DEFAULT_BANNER " PHP");

	/* Override method preferences */
	if (methods) {
		zval *container;

		if (php_ssh2_set_method(session, HASH_OF(methods), "kex", sizeof("kex") - 1, LIBSSH2_METHOD_KEX)) {
			php_error_docref(NULL, E_WARNING, "Failed overriding KEX method");
		}
		if (php_ssh2_set_method(session, HASH_OF(methods), "hostkey", sizeof("hostkey") - 1, LIBSSH2_METHOD_HOSTKEY)) {
			php_error_docref(NULL, E_WARNING, "Failed overriding HOSTKEY method");
		}

		hash_lookup_zstring = zend_string_init("client_to_server", sizeof("client_to_server") - 1, 0);
		if ((container = zend_hash_find(HASH_OF(methods), hash_lookup_zstring)) != NULL && Z_TYPE_P(container) == IS_ARRAY) {
			if (php_ssh2_set_method(session, HASH_OF(container), "crypt", sizeof("crypt") - 1, LIBSSH2_METHOD_CRYPT_CS)) {
				php_error_docref(NULL, E_WARNING, "Failed overriding client to server CRYPT method");
			}
			if (php_ssh2_set_method(session, HASH_OF(container), "mac", sizeof("mac") - 1, LIBSSH2_METHOD_MAC_CS)) {
				php_error_docref(NULL, E_WARNING, "Failed overriding client to server MAC method");
			}
			if (php_ssh2_set_method(session, HASH_OF(container), "comp", sizeof("comp") - 1, LIBSSH2_METHOD_COMP_CS)) {
				php_error_docref(NULL, E_WARNING, "Failed overriding client to server COMP method");
			}
			if (php_ssh2_set_method(session, HASH_OF(container), "lang", sizeof("lang") - 1, LIBSSH2_METHOD_LANG_CS)) {
				php_error_docref(NULL, E_WARNING, "Failed overriding client to server LANG method");
			}
		}
		zend_string_release(hash_lookup_zstring);

		hash_lookup_zstring = zend_string_init("server_to_client", sizeof("server_to_client") - 1, 0);
		if ((container = zend_hash_find(HASH_OF(methods), hash_lookup_zstring)) != NULL && Z_TYPE_P(container) == IS_ARRAY) {
			if (php_ssh2_set_method(session, HASH_OF(container), "crypt", sizeof("crypt") - 1, LIBSSH2_METHOD_CRYPT_SC)) {
				php_error_docref(NULL, E_WARNING, "Failed overriding server to client CRYPT method");
			}
			if (php_ssh2_set_method(session, HASH_OF(container), "mac", sizeof("mac") - 1, LIBSSH2_METHOD_MAC_SC)) {
				php_error_docref(NULL, E_WARNING, "Failed overriding server to client MAC method");
			}
			if (php_ssh2_set_method(session, HASH_OF(container), "comp", sizeof("comp") - 1, LIBSSH2_METHOD_COMP_SC)) {
				php_error_docref(NULL, E_WARNING, "Failed overriding server to client COMP method");
			}
			if (php_ssh2_set_method(session, HASH_OF(container), "lang", sizeof("lang") - 1, LIBSSH2_METHOD_LANG_SC)) {
				php_error_docref(NULL, E_WARNING, "Failed overriding server to client LANG method");
			}
		}
		zend_string_release(hash_lookup_zstring);

	}

	/* Register Callbacks */
	if (callbacks) {
		/* ignore debug disconnect macerror */

		if (php_ssh2_set_callback(session, HASH_OF(callbacks), "ignore", sizeof("ignore") - 1, LIBSSH2_CALLBACK_IGNORE, data)) {
			php_error_docref(NULL, E_WARNING, "Failed setting IGNORE callback");
		}

		if (php_ssh2_set_callback(session, HASH_OF(callbacks), "debug", sizeof("debug") - 1, LIBSSH2_CALLBACK_DEBUG, data)) {
			php_error_docref(NULL, E_WARNING, "Failed setting DEBUG callback");
		}

		if (php_ssh2_set_callback(session, HASH_OF(callbacks), "macerror", sizeof("macerror") - 1, LIBSSH2_CALLBACK_MACERROR, data)) {
			php_error_docref(NULL, E_WARNING, "Failed setting MACERROR callback");
		}

		if (php_ssh2_set_callback(session, HASH_OF(callbacks), "disconnect", sizeof("disconnect") - 1, LIBSSH2_CALLBACK_DISCONNECT, data)) {
			php_error_docref(NULL, E_WARNING, "Failed setting DISCONNECT callback");
		}
	}

	if (libssh2_session_startup(session, socket)) {
		int last_error = 0;
		char *error_msg = NULL;

		last_error = libssh2_session_last_error(session, &error_msg, NULL, 0);
		php_error_docref(NULL, E_WARNING, "Error starting up SSH connection(%d): %s", last_error, error_msg);
		closesocket(socket);
		libssh2_session_free(session);
		efree(data);
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
	zend_long port = PHP_SSH2_DEFAULT_PORT;
	size_t host_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|la!a!", &host, &host_len, &port, &methods, &callbacks) == FAILURE) {
		return;
	}

	session = php_ssh2_session_connect(host, port, methods, callbacks);
	if (!session) {
		php_error_docref(NULL, E_WARNING, "Unable to connect to %s", host);
		RETURN_FALSE;
	}

	RETURN_RES(zend_register_resource(session, le_ssh2_session));
}
/* }}} */

/* {{{ proto resource ssh2_disconnect(resource session)
 * close a connection to a remote SSH server and return a true on success, false on error.
 */
PHP_FUNCTION(ssh2_disconnect)
{
	zval *zsession;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &zsession) == FAILURE) {
		RETURN_FALSE;
	}

	if (zend_list_close(Z_RES_P(zsession)) != SUCCESS) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto array ssh2_methods_negotiated(resource session)
 * Return list of negotiaed methods
 */
PHP_FUNCTION(ssh2_methods_negotiated)
{
	LIBSSH2_SESSION *session;
	zval *zsession, endpoint;
	char *kex, *hostkey, *crypt_cs, *crypt_sc, *mac_cs, *mac_sc, *comp_cs, *comp_sc, *lang_cs, *lang_sc;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &zsession) == FAILURE) {
		return;
	}

	if ((session = (LIBSSH2_SESSION *)zend_fetch_resource(Z_RES_P(zsession), PHP_SSH2_SESSION_RES_NAME, le_ssh2_session)) == NULL) {
		RETURN_FALSE;
	}

	kex = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_KEX);
	hostkey = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_HOSTKEY);
	crypt_cs = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_CS);
	crypt_sc = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_SC);
	mac_cs = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_MAC_CS);
	mac_sc = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_MAC_SC);
	comp_cs = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_COMP_CS);
	comp_sc = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_COMP_SC);
	lang_cs = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_LANG_CS);
	lang_sc = (char*)libssh2_session_methods(session, LIBSSH2_METHOD_LANG_SC);

	array_init(return_value);
	add_assoc_string(return_value, "kex", kex);
	add_assoc_string(return_value, "hostkey", hostkey);

	array_init(&endpoint);
	add_assoc_string(&endpoint, "crypt", crypt_cs);
	add_assoc_string(&endpoint, "mac", mac_cs);
	add_assoc_string(&endpoint, "comp", comp_cs);
	add_assoc_string(&endpoint, "lang", lang_cs);
	add_assoc_zval(return_value, "client_to_server", &endpoint);

	array_init(&endpoint);
	add_assoc_string(&endpoint, "crypt", crypt_sc);
	add_assoc_string(&endpoint, "mac", mac_sc);
	add_assoc_string(&endpoint, "comp", comp_sc);
	add_assoc_string(&endpoint, "lang", lang_sc);
	add_assoc_zval(return_value, "server_to_client", &endpoint);
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
	const char *fingerprint;
	zend_long flags = 0;
	int i, fingerprint_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l", &zsession, &flags) == FAILURE) {
		return;
	}
	fingerprint_len = (flags & PHP_SSH2_FINGERPRINT_SHA1) ? SHA_DIGEST_LENGTH : MD5_DIGEST_LENGTH;

	if ((session = (LIBSSH2_SESSION *)zend_fetch_resource(Z_RES_P(zsession), PHP_SSH2_SESSION_RES_NAME, le_ssh2_session)) == NULL) {
		RETURN_FALSE;
	}

	fingerprint = (char*)libssh2_hostkey_hash(session, (flags & PHP_SSH2_FINGERPRINT_SHA1) ? LIBSSH2_HOSTKEY_HASH_SHA1 : LIBSSH2_HOSTKEY_HASH_MD5);
	if (!fingerprint) {
		php_error_docref(NULL, E_WARNING, "Unable to retrieve fingerprint from specified session");
		RETURN_FALSE;
	}

	for(i = 0; i < fingerprint_len; i++) {
		if (fingerprint[i] != '\0') {
			goto fingerprint_good;
		}
	}
	php_error_docref(NULL, E_WARNING, "No fingerprint available using specified hash");
	RETURN_NULL();
 fingerprint_good:
	if (flags & PHP_SSH2_FINGERPRINT_RAW) {
		RETURN_STRINGL(fingerprint, fingerprint_len);
	} else {
		char *hexchars;

		hexchars = emalloc((fingerprint_len * 2) + 1);
		for(i = 0; i < fingerprint_len; i++) {
			snprintf(hexchars + (2 * i), 3, "%02X", (unsigned char)fingerprint[i]);
		}
		ZVAL_STRINGL(return_value, hexchars, 2 * fingerprint_len);
		efree(hexchars);
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
	size_t username_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs", &zsession, &username, &username_len) == FAILURE) {
		return;
	}

	if ((session = (LIBSSH2_SESSION *)zend_fetch_resource(Z_RES_P(zsession), PHP_SSH2_SESSION_RES_NAME, le_ssh2_session)) == NULL) {
		RETURN_FALSE;
	}

	s = methods = libssh2_userauth_list(session, username, username_len);
	if (!methods) {
		/* Either bad failure, or unexpected success */
		RETURN_BOOL(libssh2_userauth_authenticated(session));
	}

	array_init(return_value);
	while ((p = strchr(s, ','))) {
		if ((p - s) > 0) {
			add_next_index_stringl(return_value, s, p - s);
		}
		s = p + 1;
	}
	if (strlen(s)) {
		add_next_index_string(return_value, s);
	}
}
/* }}} */

char *password_for_kbd_callback;

static void kbd_callback(const char *name, int name_len,
							const char *instruction, int instruction_len,
							int num_prompts,
							const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
							LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
							void **abstract)
{
	(void)name;
	(void)name_len;
	(void)instruction;
	(void)instruction_len;
	if (num_prompts == 1) {
		responses[0].text = estrdup(password_for_kbd_callback);
		responses[0].length = strlen(password_for_kbd_callback);
	}
	(void)prompts;
	(void)abstract;
}

/* {{{ proto bool ssh2_auth_password(resource session, string username, string password)
 * Authenticate over SSH using a plain password
 */
PHP_FUNCTION(ssh2_auth_password)
{
	LIBSSH2_SESSION *session;
	zval *zsession;
	zend_string *username, *password;
	char *userauthlist;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rSS", &zsession, &username, &password) == FAILURE) {
		return;
	}

	SSH2_FETCH_NONAUTHENTICATED_SESSION(session, zsession);

	userauthlist = libssh2_userauth_list(session, username->val, username->len);

	if (userauthlist != NULL) {
		password_for_kbd_callback = password->val;
		if (strstr(userauthlist, "keyboard-interactive") != NULL) {
			if (libssh2_userauth_keyboard_interactive(session, username->val, &kbd_callback) == 0) {
				RETURN_TRUE;
			}
		}

		/* TODO: Support password change callback */
		if (libssh2_userauth_password_ex(session, username->val, username->len, password->val, password->len, NULL)) {
			php_error_docref(NULL, E_WARNING, "Authentication failed for %s using password", username->val);
			RETURN_FALSE;
		}
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
	size_t username_len, pubkey_len, privkey_len, passphrase_len = 0;
#ifndef PHP_WIN32
	char *newpath;
	struct passwd *pws;
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rsss|s", &zsession,	&username, &username_len,
																				&pubkey, &pubkey_len,
																				&privkey, &privkey_len,
																				&passphrase, &passphrase_len) == FAILURE) {
		return;
	}

	if (php_check_open_basedir(pubkey) || php_check_open_basedir(privkey)) {
		RETURN_FALSE;
	}

	SSH2_FETCH_NONAUTHENTICATED_SESSION(session, zsession);
#ifndef PHP_WIN32
	/* Explode '~/paths' stopgap fix because libssh2 does not accept tilde for homedir
	  This should be ifdef'ed when a fix is available to support older libssh2 versions*/
	pws = getpwuid(geteuid());
	if (pubkey_len >= 2 && *pubkey == '~' && *(pubkey+1) == '/') {
		newpath = emalloc(strlen(pws->pw_dir) + strlen(pubkey));
		strcpy(newpath, pws->pw_dir);
		strcat(newpath, pubkey+1);
		efree(pubkey);
		pubkey = newpath;
	}
	if (privkey_len >= 2 && *privkey == '~' && *(privkey+1) == '/') {
		newpath = emalloc(strlen(pws->pw_dir) + strlen(privkey));
		strcpy(newpath, pws->pw_dir);
		strcat(newpath, privkey+1);
		efree(privkey);
		privkey = newpath;
	}
#endif

	/* TODO: Support passphrase callback */
	if (libssh2_userauth_publickey_fromfile_ex(session, username, username_len, pubkey, privkey, passphrase)) {
		char *buf;
		int len;
		libssh2_session_last_error(session, &buf, &len, 0);
		php_error_docref(NULL, E_WARNING, "Authentication failed for %s using public key: %s", username, buf);
		RETURN_FALSE;
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool ssh2_auth_hostbased_file(resource session, string username, string hostname, string pubkeyfile, string privkeyfile[, string passphrase[, string local_username]])
 * Authenticate using a hostkey
 */
PHP_FUNCTION(ssh2_auth_hostbased_file)
{
	LIBSSH2_SESSION *session;
	zval *zsession;
	char *username, *hostname, *pubkey, *privkey, *passphrase = NULL, *local_username = NULL;
	size_t username_len, hostname_len, pubkey_len, privkey_len, passphrase_len, local_username_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rssss|s!s!", &zsession,	&username, &username_len,
																					&hostname, &hostname_len,
																					&pubkey, &pubkey_len,
																					&privkey, &privkey_len,
																					&passphrase, &passphrase_len,
																					&local_username, &local_username_len) == FAILURE) {
		return;
	}

	if (php_check_open_basedir(pubkey) || php_check_open_basedir(privkey)) {
		RETURN_FALSE;
	}

	SSH2_FETCH_NONAUTHENTICATED_SESSION(session, zsession);

	if (!local_username) {
		local_username = username;
		local_username_len = username_len;
	}

	/* TODO: Support passphrase callback */
	if (libssh2_userauth_hostbased_fromfile_ex(session, username, username_len, pubkey, privkey, passphrase, hostname, hostname_len, local_username, local_username_len)) {
		php_error_docref(NULL, E_WARNING, "Authentication failed for %s using hostbased public key", username);
		RETURN_FALSE;
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto resource ssh2_forward_listen(resource session, int port[, string host[, long max_connections]])
 * Bind a port on the remote server and listen for connections
 */
PHP_FUNCTION(ssh2_forward_listen)
{
	zval *zsession;
	LIBSSH2_SESSION *session;
	LIBSSH2_LISTENER *listener;
	php_ssh2_listener_data *data;
	zend_long port;
	char *host = NULL;
	size_t host_len;
	zend_long max_connections = PHP_SSH2_LISTEN_MAX_QUEUED;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rl|sl", &zsession, &port, &host, &host_len, &max_connections) == FAILURE) {
		return;
	}

	SSH2_FETCH_AUTHENTICATED_SESSION(session, zsession);

	listener = libssh2_channel_forward_listen_ex(session, host, port, NULL, max_connections);

	if (!listener) {
		php_error_docref(NULL, E_WARNING, "Failure listening on remote port");
		RETURN_FALSE;
	}

	data = emalloc(sizeof(php_ssh2_listener_data));
	data->session = session;
	data->session_rsrc = Z_RES_P(zsession);
	Z_ADDREF_P(zsession);
	data->listener = listener;

	RETURN_RES(zend_register_resource(data, le_ssh2_listener));
}
/* }}} */

/* {{{ proto stream ssh2_forward_accept(resource listener[, string &shost[, long &sport]])
 * Accept a connection created by a listener
 */
PHP_FUNCTION(ssh2_forward_accept)
{
	zval *zlistener;
	php_ssh2_listener_data *data;
	LIBSSH2_CHANNEL *channel;
	php_ssh2_channel_data *channel_data;
	php_stream *stream;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &zlistener) == FAILURE) {
		return;
	}

	if ((data = (php_ssh2_listener_data *)zend_fetch_resource(Z_RES_P(zlistener), PHP_SSH2_LISTENER_RES_NAME, le_ssh2_listener)) == NULL) {
		RETURN_FALSE;
	}

	channel = libssh2_channel_forward_accept(data->listener);

	if (!channel) {
		RETURN_FALSE;
	}

	channel_data = emalloc(sizeof(php_ssh2_channel_data));
	channel_data->channel = channel;
	channel_data->streamid = 0;
	channel_data->is_blocking = 0;
	channel_data->session_rsrc = data->session_rsrc;
	channel_data->refcount = NULL;

	stream = php_stream_alloc(&php_ssh2_channel_stream_ops, channel_data, 0, "r+");
	if (!stream) {
		php_error_docref(NULL, E_WARNING, "Failure allocating stream");
		efree(channel_data);
		libssh2_channel_free(channel);
		RETURN_FALSE;
	}
	// For PHP 7.3
	GC_ADDREF(channel_data->session_rsrc);

	php_stream_to_zval(stream, return_value);
}
/* }}} */

/* {{{ proto int ssh2_poll(array &polldes[, int timeout])
 * Poll the channels/listeners/streams for events
 * Returns number of descriptors which returned non-zero revents
 * Input array should be of the form:
 * array(
 *   0 => array(
 *     [resource] => $channel,$listener, or $stream
 *     [events] => SSH2_POLL* flags bitwise ORed together
 *   ),
 *   1 => ...
 * )
 * Each subarray will be populated with an revents element on return
 */
PHP_FUNCTION(ssh2_poll)
{
	zval *zdesc, *subarray, ***pollmap;
	zend_long timeout = PHP_SSH2_DEFAULT_POLL_TIMEOUT;
	LIBSSH2_POLLFD *pollfds;
	int numfds, i = 0, fds_ready;
	int le_stream = php_file_le_stream();
	int le_pstream = php_file_le_pstream();
	zend_string *hash_key_zstring;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "a|l", &zdesc, &timeout) == FAILURE) {
		return;
	}

	numfds = zend_hash_num_elements(Z_ARRVAL_P(zdesc));
	pollfds = safe_emalloc(sizeof(LIBSSH2_POLLFD), numfds, 0);
	pollmap = safe_emalloc(sizeof(zval**), numfds, 0);

	for(zend_hash_internal_pointer_reset(Z_ARRVAL_P(zdesc));
		(subarray = zend_hash_get_current_data(Z_ARRVAL_P(zdesc))) != NULL;
		zend_hash_move_forward(Z_ARRVAL_P(zdesc))) {
		zval *tmpzval;
		int res_type = 0;
		void *res;

		if (Z_TYPE_P(subarray) != IS_ARRAY) {
			php_error_docref(NULL, E_WARNING, "Invalid element in poll array, not a sub array");
			numfds--;
			continue;
		}

		hash_key_zstring = zend_string_init("events", sizeof("events") - 1, 0);
		if ((tmpzval = zend_hash_find(Z_ARRVAL_P(subarray), hash_key_zstring)) == NULL || Z_TYPE_P(tmpzval) != IS_LONG) {
			php_error_docref(NULL, E_WARNING, "Invalid data in subarray, no events element, or not a bitmask");
			numfds--;
			zend_string_release(hash_key_zstring);
			continue;
		}
		zend_string_release(hash_key_zstring);

		pollfds[i].events = Z_LVAL_P(tmpzval);
		hash_key_zstring = zend_string_init("resource", sizeof("resource") - 1, 0);
		if ((tmpzval = zend_hash_find(Z_ARRVAL_P(subarray), hash_key_zstring)) == NULL || Z_TYPE_P(tmpzval) != IS_RESOURCE) {
			php_error_docref(NULL, E_WARNING, "Invalid data in subarray, no resource element, or not of type resource");
			numfds--;
			zend_string_release(hash_key_zstring);
			continue;
		}
		zend_string_release(hash_key_zstring);

		res_type = Z_RES_P(tmpzval)->type;
		res = zend_fetch_resource_ex(tmpzval, "Poll Resource", res_type);
		if (res_type == le_ssh2_listener) {
			pollfds[i].type = LIBSSH2_POLLFD_LISTENER;
			pollfds[i].fd.listener = ((php_ssh2_listener_data*)res)->listener;
		} else if ((res_type == le_stream || res_type == le_pstream) &&
				   ((php_stream*)res)->ops == &php_ssh2_channel_stream_ops) {
			pollfds[i].type = LIBSSH2_POLLFD_CHANNEL;
			pollfds[i].fd.channel = ((php_ssh2_channel_data*)(((php_stream*)res)->abstract))->channel;
			/* TODO: Add the ability to select against other stream types */
		} else {
			php_error_docref(NULL, E_WARNING, "Invalid resource type in subarray: %s", zend_rsrc_list_get_rsrc_type(Z_RES_P(tmpzval)));
			numfds--;
			continue;
		}
		pollmap[i] = &subarray;
		i++;
	}

	fds_ready = libssh2_poll(pollfds, numfds, timeout * 1000);

	for(i = 0; i < numfds; i++) {
		zval *subarray = *pollmap[i];

		if (!Z_ISREF_P(subarray) && Z_REFCOUNT_P(subarray) > 1) {
			/* Make a new copy of the subarray zval* */
			// TODO Sean-Der
			//MAKE_STD_ZVAL(subarray);
			*subarray = **pollmap[i];

			/* Point the pData to the new zval* and duplicate its resources */
			*pollmap[i] = subarray;
			zval_copy_ctor(subarray);

			/* Fixup its refcount */
			// TODO Sean-Der
			//Z_UNSET_ISREF_P(subarray);
			//Z_SET_REFCOUNT_P(subarray, 1);
		}
		hash_key_zstring = zend_string_init("revents", sizeof("revents") - 1, 0);
		zend_hash_del(Z_ARRVAL_P(subarray), hash_key_zstring);
		zend_string_release(hash_key_zstring);

		add_assoc_long(subarray, "revents", pollfds[i].revents);

	}
	efree(pollmap);
	efree(pollfds);

	RETURN_LONG(fds_ready);
}
/* }}} */

/* ***********************
   * Publickey Subsystem *
   *********************** */

/* {{{ proto resource ssh2_publickey_init(resource connection)
Initialize the publickey subsystem */
PHP_FUNCTION(ssh2_publickey_init)
{
	zval *zsession;
	LIBSSH2_SESSION *session;
	LIBSSH2_PUBLICKEY *pkey;
	php_ssh2_pkey_subsys_data *data;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &zsession) == FAILURE) {
		return;
	}

	SSH2_FETCH_AUTHENTICATED_SESSION(session, zsession);

	pkey = libssh2_publickey_init(session);

	if (!pkey) {
		int last_error = 0;
		char *error_msg = NULL;

		last_error = libssh2_session_last_error(session, &error_msg, NULL, 0);
		php_error_docref(NULL, E_WARNING, "Unable to initialize publickey subsystem(%d) %s", last_error, error_msg);
		RETURN_FALSE;
	}

	data = emalloc(sizeof(php_ssh2_pkey_subsys_data));
	data->session = session;
	data->session_rsrc = Z_RES_P(zsession);
	Z_ADDREF_P(zsession);
	data->pkey = pkey;

	RETURN_RES(zend_register_resource(data, le_ssh2_pkey_subsys));
}
/* }}} */

/* {{{ proto bool ssh2_publickey_add(resource pkey, string algoname, string blob[, bool overwrite=FALSE [,array attributes=NULL]])
Add an additional publickey */
PHP_FUNCTION(ssh2_publickey_add)
{
	zval *zpkey_data, *zattrs = NULL;
	php_ssh2_pkey_subsys_data *data;
	char *algo, *blob;
	size_t algo_len, blob_len;
	unsigned long num_attrs = 0;
	libssh2_publickey_attribute *attrs = NULL;
	zend_bool overwrite = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rss|ba", &zpkey_data, &algo, &algo_len, &blob, &blob_len, &overwrite, &zattrs) == FAILURE) {
		return;
	}

	if ((data = (php_ssh2_pkey_subsys_data *)zend_fetch_resource(Z_RES_P(zpkey_data), PHP_SSH2_PKEY_SUBSYS_RES_NAME, le_ssh2_pkey_subsys)) == NULL) {
		RETURN_FALSE;
	}

	if (zattrs) {
		HashPosition pos;
		zval *attr_val;
		unsigned long current_attr = 0;

		num_attrs = zend_hash_num_elements(Z_ARRVAL_P(zattrs));
		attrs = safe_emalloc(num_attrs, sizeof(libssh2_publickey_attribute), 0);

		for(zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(zattrs), &pos);
			(attr_val = zend_hash_get_current_data_ex(Z_ARRVAL_P(zattrs), &pos)) != NULL;
			zend_hash_move_forward_ex(Z_ARRVAL_P(zattrs), &pos)) {
			zend_string *key;
			int type;
			zend_ulong idx;
			zval copyval = *attr_val;

			type = zend_hash_get_current_key_ex(Z_ARRVAL_P(zattrs), &key, &idx, &pos);
			if (type == HASH_KEY_NON_EXISTENT) {
				/* All but impossible */
				break;
			}
			if (type == HASH_KEY_IS_LONG) {
				/* Malformed, ignore */
				php_error_docref(NULL, E_WARNING, "Malformed attirbute array, contains numeric index");
				num_attrs--;
				continue;
			}

			if (!key || (key->len == 1 && key->val[0] == '*')) {
				/* Empty key, ignore */
				php_error_docref(NULL, E_WARNING, "Empty attribute key");
				num_attrs--;
				continue;
			}

			zval_copy_ctor(&copyval);
			// TODO Sean-Der
			//Z_UNSET_ISREF_P(&copyval);
			//Z_SET_REFCOUNT_P(&copyval, 1);
			convert_to_string(&copyval);

			if (key->val[0] == '*') {
				attrs[current_attr].mandatory = 1;
				attrs[current_attr].name = key->val + 1;
				attrs[current_attr].name_len = key->len - 2;
			} else {
				attrs[current_attr].mandatory = 0;
				attrs[current_attr].name = key->val;
				attrs[current_attr].name_len = key->len - 1;
			}
			attrs[current_attr].value_len = Z_STRLEN(copyval);
			attrs[current_attr].value = Z_STRVAL(copyval);

			/* copyval deliberately not dtor'd, we're stealing the string */
			current_attr++;
		}
	}

	if (libssh2_publickey_add_ex(data->pkey, (unsigned char *) algo, algo_len, (unsigned char *) blob, blob_len, overwrite, num_attrs, attrs)) {
		php_error_docref(NULL, E_WARNING, "Unable to add %s key", algo);
		RETVAL_FALSE;
	} else {
		RETVAL_TRUE;
	}

	if (attrs) {
		unsigned long i;

		for(i = 0; i < num_attrs; i++) {
			/* name doesn't need freeing */
			// TODO Sean-Der
			//efree(attrs[i].value);
		}
		efree(attrs);
	}
}
/* }}} */

/* {{{ proto bool ssh2_publickey_remove(resource pkey, string algoname, string blob)
Remove a publickey entry */
PHP_FUNCTION(ssh2_publickey_remove)
{
	zval *zpkey_data;
	php_ssh2_pkey_subsys_data *data;
	char *algo, *blob;
	size_t algo_len, blob_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rss", &zpkey_data, &algo, &algo_len, &blob, &blob_len) == FAILURE) {
		return;
	}

	if ((data = (php_ssh2_pkey_subsys_data *)zend_fetch_resource(Z_RES_P(zpkey_data), PHP_SSH2_PKEY_SUBSYS_RES_NAME, le_ssh2_pkey_subsys)) == NULL) {
		RETURN_FALSE;
	}

	if (libssh2_publickey_remove_ex(data->pkey, (unsigned char *) algo, algo_len, (unsigned char *) blob, blob_len)) {
		php_error_docref(NULL, E_WARNING, "Unable to remove %s key", algo);
		RETURN_FALSE;
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto array ssh2_publickey_list(resource pkey)
List currently installed publickey entries */
PHP_FUNCTION(ssh2_publickey_list)
{
	zval *zpkey_data;
	php_ssh2_pkey_subsys_data *data;
	unsigned long num_keys, i;
	libssh2_publickey_list *keys;
	zend_string *hash_key_zstring;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &zpkey_data) == FAILURE) {
		return;
	}

	if ((data = (php_ssh2_pkey_subsys_data *)zend_fetch_resource(Z_RES_P(zpkey_data), PHP_SSH2_PKEY_SUBSYS_RES_NAME, le_ssh2_pkey_subsys)) == NULL) {
		RETURN_FALSE;
	}

	if (libssh2_publickey_list_fetch(data->pkey, &num_keys, &keys)) {
		php_error_docref(NULL, E_WARNING, "Unable to list keys on remote server");
		RETURN_FALSE;
	}

	array_init(return_value);
	for(i = 0; i < num_keys; i++) {
		zval key, attrs;
		unsigned long j;

		array_init(&key);

		add_assoc_stringl(&key, "name", (char *) keys[i].name, keys[i].name_len);
		add_assoc_stringl(&key, "blob", (char *) keys[i].blob, keys[i].blob_len);

		array_init(&attrs);
		for(j = 0; j < keys[i].num_attrs; j++) {
			zval attr;

			ZVAL_STRINGL(&attr, keys[i].attrs[j].value, keys[i].attrs[j].value_len);
			hash_key_zstring = zend_string_init(keys[i].attrs[j].name, keys[i].attrs[j].name_len, 0);
			zend_hash_add(Z_ARRVAL_P(&attrs), hash_key_zstring, &attr);
			zend_string_release(hash_key_zstring);
		}
		add_assoc_zval(&key, "attrs", &attrs);

		add_next_index_zval(return_value, &key);
	}

	libssh2_publickey_list_free(data->pkey, keys);
}
/* }}} */

/* {{{ proto array ssh2_auth_agent(resource session, string username)
Authenticate using the ssh agent */
PHP_FUNCTION(ssh2_auth_agent)
{
#ifdef PHP_SSH2_AGENT_AUTH
	zval *zsession;
	char *username;
	size_t username_len;

	LIBSSH2_SESSION *session;
	char *userauthlist;
	LIBSSH2_AGENT *agent = NULL;
	int rc;
	struct libssh2_agent_publickey *identity, *prev_identity = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs", &zsession, &username, &username_len) == FAILURE) {
		return;
	}

	SSH2_FETCH_NONAUTHENTICATED_SESSION(session, zsession);

	/* check what authentication methods are available */
	userauthlist = libssh2_userauth_list(session, username, username_len);

	if (userauthlist != NULL && strstr(userauthlist, "publickey") == NULL) {
		php_error_docref(NULL, E_WARNING, "\"publickey\" authentication is not supported");
		RETURN_FALSE;
	}

	/* Connect to the ssh-agent */
	agent = libssh2_agent_init(session);

	if (!agent) {
		php_error_docref(NULL, E_WARNING, "Failure initializing ssh-agent support");
		RETURN_FALSE;
	}

	if (libssh2_agent_connect(agent)) {
		php_error_docref(NULL, E_WARNING, "Failure connecting to ssh-agent");
		libssh2_agent_free(agent);
		RETURN_FALSE;
	}

	if (libssh2_agent_list_identities(agent)) {
		php_error_docref(NULL, E_WARNING, "Failure requesting identities to ssh-agent");
		libssh2_agent_disconnect(agent);
		libssh2_agent_free(agent);
		RETURN_FALSE;
	}

	while (1) {
		rc = libssh2_agent_get_identity(agent, &identity, prev_identity);

		if (rc == 1) {
			php_error_docref(NULL, E_WARNING, "Couldn't continue authentication");
			libssh2_agent_disconnect(agent);
			libssh2_agent_free(agent);
			RETURN_FALSE;
		}

		if (rc < 0) {
			php_error_docref(NULL, E_WARNING, "Failure obtaining identity from ssh-agent support");
			libssh2_agent_disconnect(agent);
			libssh2_agent_free(agent);
			RETURN_FALSE;
		}

		if (!libssh2_agent_userauth(agent, username, identity)) {
			libssh2_agent_disconnect(agent);
			libssh2_agent_free(agent);
			RETURN_TRUE;
		}
		prev_identity = identity;
	}
#else
	php_error_docref(NULL, E_WARNING, "Upgrade the libssh2 library (needs 1.2.3 or higher) and reinstall the ssh2 extension for ssh2 agent support");
	RETURN_FALSE;
#endif /* PHP_SSH2_AGENT_AUTH */
}
/* }}} */

/* ***********************
   * Module Housekeeping *
   *********************** */

static void php_ssh2_session_dtor(zend_resource *rsrc)
{
	LIBSSH2_SESSION *session = (LIBSSH2_SESSION*)rsrc->ptr;
	php_ssh2_session_data **data = (php_ssh2_session_data**)libssh2_session_abstract(session);

	libssh2_session_disconnect(session, "PECL/ssh2 (http://pecl.php.net/packages/ssh2)");

	if (*data) {
		if ((*data)->ignore_cb) {
			zval_ptr_dtor((*data)->ignore_cb);
		}
		if ((*data)->debug_cb) {
			zval_ptr_dtor((*data)->debug_cb);
		}
		if ((*data)->macerror_cb) {
			zval_ptr_dtor((*data)->macerror_cb);
		}
		if ((*data)->disconnect_cb) {
			zval_ptr_dtor((*data)->disconnect_cb);
		}

		closesocket((*data)->socket);

		efree(*data);
		*data = NULL;
	}

	libssh2_session_free(session);
}

static void php_ssh2_listener_dtor(zend_resource *rsrc)
{
	php_ssh2_listener_data *data = (php_ssh2_listener_data*)rsrc->ptr;
	LIBSSH2_LISTENER *listener = data->listener;

	libssh2_channel_forward_cancel(listener);
	zend_list_delete(data->session_rsrc);
	efree(data);
}

static void php_ssh2_pkey_subsys_dtor(zend_resource *rsrc)
{
	php_ssh2_pkey_subsys_data *data = (php_ssh2_pkey_subsys_data*)rsrc->ptr;
	LIBSSH2_PUBLICKEY *pkey = data->pkey;

	libssh2_publickey_shutdown(pkey);
	zend_list_delete(data->session_rsrc);
	efree(data);
}

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(ssh2)
{
	le_ssh2_session		= zend_register_list_destructors_ex(php_ssh2_session_dtor, NULL, PHP_SSH2_SESSION_RES_NAME, module_number);
	le_ssh2_listener	= zend_register_list_destructors_ex(php_ssh2_listener_dtor, NULL, PHP_SSH2_LISTENER_RES_NAME, module_number);
	le_ssh2_sftp		= zend_register_list_destructors_ex(php_ssh2_sftp_dtor, NULL, PHP_SSH2_SFTP_RES_NAME, module_number);
	le_ssh2_pkey_subsys	= zend_register_list_destructors_ex(php_ssh2_pkey_subsys_dtor, NULL, PHP_SSH2_PKEY_SUBSYS_RES_NAME, module_number);

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

	/* events/revents */
	REGISTER_LONG_CONSTANT("SSH2_POLLIN",				LIBSSH2_POLLFD_POLLIN,			CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_POLLEXT",				LIBSSH2_POLLFD_POLLEXT,			CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_POLLOUT",				LIBSSH2_POLLFD_POLLOUT,			CONST_CS | CONST_PERSISTENT);

	/* revents only */
	REGISTER_LONG_CONSTANT("SSH2_POLLERR",				LIBSSH2_POLLFD_POLLERR,			CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_POLLHUP",				LIBSSH2_POLLFD_POLLHUP,			CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_POLLNVAL",				LIBSSH2_POLLFD_POLLNVAL,		CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_POLL_SESSION_CLOSED",	LIBSSH2_POLLFD_SESSION_CLOSED,	CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_POLL_CHANNEL_CLOSED",	LIBSSH2_POLLFD_CHANNEL_CLOSED,	CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("SSH2_POLL_LISTENER_CLOSED",	LIBSSH2_POLLFD_LISTENER_CLOSED,	CONST_CS | CONST_PERSISTENT);

	return (php_register_url_stream_wrapper("ssh2.shell", &php_ssh2_stream_wrapper_shell) == SUCCESS &&
			php_register_url_stream_wrapper("ssh2.exec", &php_ssh2_stream_wrapper_exec) == SUCCESS &&
			php_register_url_stream_wrapper("ssh2.tunnel", &php_ssh2_stream_wrapper_tunnel) == SUCCESS &&
			php_register_url_stream_wrapper("ssh2.scp", &php_ssh2_stream_wrapper_scp) == SUCCESS &&
			php_register_url_stream_wrapper("ssh2.sftp", &php_ssh2_sftp_wrapper) == SUCCESS) ? SUCCESS : FAILURE;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(ssh2)
{
	return (php_unregister_url_stream_wrapper("ssh2.shell") == SUCCESS &&
			php_unregister_url_stream_wrapper("ssh2.exec") == SUCCESS &&
			php_unregister_url_stream_wrapper("ssh2.tunnel") == SUCCESS &&
			php_unregister_url_stream_wrapper("ssh2.scp") == SUCCESS &&
			php_unregister_url_stream_wrapper("ssh2.sftp") == SUCCESS) ? SUCCESS : FAILURE;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(ssh2)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "SSH2 support", "enabled");
	php_info_print_table_row(2, "extension version", PHP_SSH2_VERSION);
	php_info_print_table_row(2, "libssh2 version", LIBSSH2_VERSION);
	php_info_print_table_row(2, "banner", LIBSSH2_SSH_BANNER);
	php_info_print_table_end();
}
/* }}} */

/* {{{ ZEND_BEGIN_ARG_INFO
 */
ZEND_BEGIN_ARG_INFO_EX(arginfo_ssh2_connect, 0, 0, 1)
 	ZEND_ARG_INFO(0, host)
 	ZEND_ARG_INFO(0, port)
 	ZEND_ARG_INFO(0, methods)
 	ZEND_ARG_INFO(0, callbacks)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_disconnect, 1)
 	ZEND_ARG_INFO(0, session)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_methods_negotiated, 1)
 	ZEND_ARG_INFO(0, session)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ssh2_fingerprint, 0, 0, 1)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_auth_none, 2)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, username)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_auth_password, 3)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, username)
 	ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ssh2_auth_pubkey_file, 0, 0, 4)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, username)
 	ZEND_ARG_INFO(0, pubkeyfile)
 	ZEND_ARG_INFO(0, privkeyfile)
 	ZEND_ARG_INFO(0, passphrase)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ssh2_auth_hostbased_file, 0, 0, 5)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, username)
 	ZEND_ARG_INFO(0, hostname)
 	ZEND_ARG_INFO(0, pubkeyfile)
 	ZEND_ARG_INFO(0, privkeyfile)
 	ZEND_ARG_INFO(0, passphrase)
 	ZEND_ARG_INFO(0, local_username)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ssh2_shell, 0, 0, 1)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, termtype)
 	ZEND_ARG_INFO(0, env)
 	ZEND_ARG_INFO(0, width)
 	ZEND_ARG_INFO(0, height)
 	ZEND_ARG_INFO(0, width_height_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ssh2_exec, 0, 0, 2)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, command)
 	ZEND_ARG_INFO(0, pty)
 	ZEND_ARG_INFO(0, env)
 	ZEND_ARG_INFO(0, width)
 	ZEND_ARG_INFO(0, height)
 	ZEND_ARG_INFO(0, width_height_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_tunnel, 3)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, host)
 	ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_scp_recv, 3)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, remote_file)
 	ZEND_ARG_INFO(0, local_file)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ssh2_scp_send, 0, 0, 3)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, local_file)
 	ZEND_ARG_INFO(0, remote_file)
 	ZEND_ARG_INFO(0, create_mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_fetch_stream, 2)
 	ZEND_ARG_INFO(0, channel)
 	ZEND_ARG_INFO(0, streamid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp, 1)
 	ZEND_ARG_INFO(0, session)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp_rename, 3)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, from)
 	ZEND_ARG_INFO(0, to)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp_unlink, 2)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ssh2_sftp_mkdir, 0, 0, 2)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, dirname)
 	ZEND_ARG_INFO(0, mode)
 	ZEND_ARG_INFO(0, recursive)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp_rmdir, 2)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, dirname)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp_chmod, 3)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, filename)
 	ZEND_ARG_INFO(0, mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp_stat, 2)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp_lstat, 2)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp_symlink, 3)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, target)
 	ZEND_ARG_INFO(0, link)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp_readlink, 2)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, link)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_sftp_realpath, 2)
 	ZEND_ARG_INFO(0, sftp)
 	ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_publickey_init, 1)
 	ZEND_ARG_INFO(0, session)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ssh2_publickey_add, 0, 0, 3)
 	ZEND_ARG_INFO(0, pkey)
 	ZEND_ARG_INFO(0, algoname)
 	ZEND_ARG_INFO(0, blob)
 	ZEND_ARG_INFO(0, overwrite)
 	ZEND_ARG_INFO(0, attributes)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_publickey_remove, 3)
 	ZEND_ARG_INFO(0, pkey)
 	ZEND_ARG_INFO(0, algoname)
 	ZEND_ARG_INFO(0, blob)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_publickey_list, 1)
 	ZEND_ARG_INFO(0, pkey)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_ssh2_auth_agent, 2)
 	ZEND_ARG_INFO(0, session)
 	ZEND_ARG_INFO(0, username)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ ssh2_functions[]
 */
zend_function_entry ssh2_functions[] = {
	PHP_FE(ssh2_connect,						arginfo_ssh2_connect)
	PHP_FE(ssh2_disconnect,						arginfo_ssh2_disconnect)
	PHP_FE(ssh2_methods_negotiated,				arginfo_ssh2_methods_negotiated)
	PHP_FE(ssh2_fingerprint,					arginfo_ssh2_fingerprint)

	PHP_FE(ssh2_auth_none,						arginfo_ssh2_auth_none)
	PHP_FE(ssh2_auth_password,					arginfo_ssh2_auth_password)
	PHP_FE(ssh2_auth_pubkey_file,				arginfo_ssh2_auth_pubkey_file)
	PHP_FE(ssh2_auth_hostbased_file,			arginfo_ssh2_auth_hostbased_file)

	PHP_FE(ssh2_forward_listen,					NULL)
	PHP_FE(ssh2_forward_accept,					NULL)

	/* Stream Stuff */
	PHP_FE(ssh2_shell,							arginfo_ssh2_shell)
	PHP_FE(ssh2_exec,							arginfo_ssh2_exec)
	PHP_FE(ssh2_tunnel,							arginfo_ssh2_tunnel)
	PHP_FE(ssh2_scp_recv,						arginfo_ssh2_scp_recv)
	PHP_FE(ssh2_scp_send,						arginfo_ssh2_scp_send)
	PHP_FE(ssh2_fetch_stream,					arginfo_ssh2_fetch_stream)
	PHP_FE(ssh2_poll,							php_ssh2_first_arg_force_ref)

	/* SFTP Stuff */
	PHP_FE(ssh2_sftp,							arginfo_ssh2_sftp)

	/* SFTP Wrapper Ops */
	PHP_FE(ssh2_sftp_rename,					arginfo_ssh2_sftp_rename)
	PHP_FE(ssh2_sftp_unlink,					arginfo_ssh2_sftp_unlink)
	PHP_FE(ssh2_sftp_mkdir,						arginfo_ssh2_sftp_mkdir)
	PHP_FE(ssh2_sftp_rmdir,						arginfo_ssh2_sftp_rmdir)
	PHP_FE(ssh2_sftp_chmod,						arginfo_ssh2_sftp_chmod)
	PHP_FE(ssh2_sftp_stat,						arginfo_ssh2_sftp_stat)
	PHP_FE(ssh2_sftp_lstat,						arginfo_ssh2_sftp_lstat)
	PHP_FE(ssh2_sftp_symlink,					arginfo_ssh2_sftp_symlink)
	PHP_FE(ssh2_sftp_readlink,					arginfo_ssh2_sftp_readlink)
	PHP_FE(ssh2_sftp_realpath,					arginfo_ssh2_sftp_realpath)

	/* Publickey subsystem */
	PHP_FE(ssh2_publickey_init,					arginfo_ssh2_publickey_init)
	PHP_FE(ssh2_publickey_add,					arginfo_ssh2_publickey_add)
	PHP_FE(ssh2_publickey_remove,				arginfo_ssh2_publickey_remove)
	PHP_FE(ssh2_publickey_list,					arginfo_ssh2_publickey_list)

	PHP_FE(ssh2_auth_agent,						arginfo_ssh2_auth_agent)

	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ ssh2_module_entry
 */
zend_module_entry ssh2_module_entry = {
	STANDARD_MODULE_HEADER,
	"ssh2",
	ssh2_functions,
	PHP_MINIT(ssh2),
	PHP_MSHUTDOWN(ssh2),
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	PHP_MINFO(ssh2),
	PHP_SSH2_VERSION,
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
