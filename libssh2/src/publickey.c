/* Copyright (c) 2004-2005, Sara Golemon <sarag@libssh2.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "libssh2_priv.h"

struct _LIBSSH2_PUBLICKEY {
	LIBSSH2_CHANNEL *channel;
	unsigned long version;
	unsigned long status;
};

#define LIBSSH2_PUBLICKEY_VERSION				2

/* PUBLICKEY status codes */
#define LIBSSH2_PUBLICKEY_SUCCESS				0
#define LIBSSH2_PUBLICKEY_ACCESS_DENIED			1
#define LIBSSH2_PUBLICKEY_STORAGE_EXCEEDED		2
#define LIBSSH2_PUBLICKEY_VERSION_NOT_SUPPORTED	3
#define LIBSSH2_PUBLICKEY_KEY_NOT_FOUND			4
#define LIBSSH2_PUBLICKEY_KEY_NOT_SUPPORTED		5
#define LIBSSH2_PUBLICKEY_KEY_ALREADY_PRESENT	6
#define LIBSSH2_PUBLICKEY_GENERAL_FAILURE		7
#define LIBSSH2_PUBLICKEY_REQUEST_NOT_SUPPORTED	8

/* {{{ libssh2_publickey_packet_require
 * Require the named packet
 * If a status packet is received instead, return NULL/0 in data/data_len and set pkey->status
 * Resets status on each call
 */
/* Macro expects name to be a static string */
#define libssh2_publickey_packet_require(pkey, name, data, data_len) \
	_libssh2_publickey_packet_require((pkey), (name), sizeof(name) - 1, (data), (data_len))
static int _libssh2_publickey_read_packet(LIBSSH2_PUBLICKEY *pkey, const unsigned char *name, unsigned long name_len,
																	unsigned char **data, unsigned long *data_len)
{

}
/* }}} */

/* {{{ libssh2_publickey_init
 * Startup the publickey subsystem
 */
LIBSSH2_API LIBSSH2_PUBLICKEY *libssh2_publickey_init(LIBSSH2_SESSION *session)
{
	LIBSSH2_PUBLICKEY *pkey;
	LIBSSH2_CHANNEL *channel;
	unsigned char buffer[15];	/* version_len(4) + "version"(7) + version_num(4) */
	unsigned char *s, *data;
	unsigned long data_len;

#ifdef LIBSSH2_DEBUG_PUBLICKEY
	_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Initializing publickey subsystem");
#endif

	channel = libssh2_channel_open_session(session);
	if (!channel) {
		libssh2_error(session, LIBSSH2_ERROR_CHANNEL_FAILURE, "Unable to startup channel", 0);
		return NULL;
	}
	if (libssh2_channel_subsystem(channel, "publickey")) {
		libssh2_error(session, LIBSSH2_ERROR_CHANNEL_FAILURE, "Unable to request publickey subsystem", 0);
		libssh2_channel_free(channel);
		return NULL;
	}

	libssh2_channel_set_blocking(channel, 1);
	libssh2_channel_handle_extended_data(channel, LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE);

	pkey = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_PUBLICKEY));
	if (!pkey) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate a new publickey structure", 0);
		libssh2_channel_free(channel);
		return NULL;
	}
	pkey->channel = channel;
	pkey->status = 0;

	s = buffer;
	libssh2_htonu32(s, sizeof("version") - 1);			s += 4;
	memcpy(s, "version", sizeof("version") - 1);		s += sizeof("version") - 1;
	libssh2_hontu32(s, LIBSSH2_PUBLICKEY_VERSION);

#ifdef LIBSSH2_DEBUG_PUBLICKEY
	_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Sending publickey version packet advertising version %d support", (int)LIBSSH2_PUBLICKEY_VERSION);
#endif
    if ((s - buffer) != libssh2_channel_write(channel, buffer, (s - buffer))) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send publickey version packet", 0);
        libssh2_channel_free(channel);
        LIBSSH2_FREE(session, pkey);
        return NULL;
    }

	if (libssh2_publickey_packet_require(pkey, "version", &data, &data_len)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT, "Timeout waiting for response from publickey subsystem", 0);
		libssh2_channel_free(channel);
		LIBSSH2_FREE(session, pkey);
		return NULL;
	}

	if (!data || data_len < (4 + sizeof("version") - 1 + 4) || pkey->status != LIBSSH2_PUBLICKEY_SUCCESS) {
		if (pkey->status == LIBSSH2_PUBLICKEY_VERSION_NOT_SUPPORTED) {
			libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Invalid version response", 0);
		} else {
			/* Bad response */
			libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Invalid version response", 0);
		}
		libssh2_channel_free(channel);
		LIBSSH2_FREE(session, pkey);
		return NULL;
	}

	pkey->version = libssh2_ntohu32(data + 4 + sizeof("version") - 1);
	if (pkey->version > LIBSSH2_PUBLICKEY_VERSION) {
#ifdef LIBSSH2_DEBUG_PUBLICKEY
		_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Truncating remote publickey version from %lu", pkey->version);
#endif
		pkey->version = LIBSSH2_PUBLICKEY_VERSION;
	}
#ifdef LIBSSH2_DEBUG_PUBLICKEY
		_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Enabling publickey subsystem version %lu", pkey->version);
#endif

	LIBSSH2_FREE(session, data);
	pkey->channel->abstract = pkey;
	pkey->channel->close_cb = libssh2_publickey_dtor;

	return pkey;
}
/* }}} */
