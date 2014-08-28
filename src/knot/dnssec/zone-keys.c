/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>

#include "common/debug.h"
#include "common/mem.h"
#include "dnssec/error.h"
#include "dnssec/kasp.h"
#include "dnssec/keystore.h"
#include "dnssec/sign.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/common.h"
#include "libknot/consts.h"
#include "libknot/dname.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/dnskey.h"

/*!
 * \brief Get zone key by a keytag.
 */
zone_key_t *get_zone_key(const zone_keyset_t *keyset, uint16_t search)
{
	if (!keyset) {
		return NULL;
	}

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		uint16_t keytag = dnssec_key_get_keytag(key->key);
		if (keytag == search) {
			return key;
		}
	}

	return NULL;
}

/*!
 * \brief Get key feature flags from key parameters.
 */
static int set_key(dnssec_kasp_key_t *kasp_key, zone_key_t *zone_key)
{
	assert(kasp_key);
	assert(zone_key);

	time_t now = time(NULL);
	dnssec_kasp_key_timing_t *timing = &kasp_key->timing;

	// cryptographic context

	dnssec_sign_ctx_t *ctx = NULL;
	int r = dnssec_sign_new(&ctx, kasp_key->key);
	if (r != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	zone_key->key = kasp_key->key;
	zone_key->ctx = ctx;

	// next event computation

	time_t next = LONG_MAX;
	time_t timestamps[4] = {
	        timing->active,
		timing->publish,
	        timing->remove,
	        timing->retire,
	};

	for (int i = 0; i < 4; i++) {
		time_t ts = timestamps[i];
		if (ts != 0 && now < ts && ts < next) {
			next = ts;
		}
	}

	zone_key->next_event = next;

	// build flags

	uint16_t flags = dnssec_key_get_flags(kasp_key->key);
	zone_key->is_ksk = flags & KNOT_RDATA_DNSKEY_FLAG_KSK;
	zone_key->is_zsk = !zone_key->is_ksk;

	zone_key->is_active = timing->active <= now &&
	                      (timing->retire == 0 || now < timing->retire);
	zone_key->is_public = timing->publish <= now &&
	                      (timing->remove == 0 || now < timing->remove);

	return KNOT_EOK;
}

/*!
 * \brief Load private keys for active keys.
 */
static int load_private_keys(const char *kasp_dir, zone_keyset_t *keyset)
{
	assert(kasp_dir);
	assert(keyset);

	int result = KNOT_EOK;
	char *keystore_dir = NULL;
	dnssec_keystore_t *keystore = NULL;

	int length = asprintf(&keystore_dir, "%s/keys", kasp_dir);
	if (length < 0) {
		result = KNOT_ENOMEM;
		goto fail;
	}

	result = dnssec_keystore_create_pkcs8_dir(&keystore, keystore_dir);
	if (result != DNSSEC_EOK) {
		goto fail;
	}

	for (size_t i = 0; i < keyset->count; i++) {
		if (!keyset->keys[i].is_active) {
			continue;
		}

		dnssec_key_t *key = keyset->keys[i].key;
		result = dnssec_key_import_private_keystore(key, keystore);
		if (result != DNSSEC_EOK) {
			result = KNOT_DNSSEC_EINVALID_KEY;
			break;
		}
	}

	result = KNOT_EOK;
fail:
	dnssec_keystore_close(keystore);
	free(keystore_dir);

	return result;
}

/*!
 * \brief Check if there is a functional KSK and ZSK for each used algorithm.
 *
 * \todo [dnssec] move to library
 */
static int check_keys_validity(const zone_keyset_t *keyset)
{
	assert(keyset);

	const int MAX_ALGORITHMS = DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384 + 1;
	struct {
		bool published;
		bool ksk_enabled;
		bool zsk_enabled;
	} algorithms[MAX_ALGORITHMS];
	memset(algorithms, 0, sizeof(algorithms));

	/* Make a list of used algorithms */

	for (size_t i = 0; i < keyset->count; i++) {
		const zone_key_t *key = &keyset->keys[i];
		dnssec_key_algorithm_t a = dnssec_key_get_algorithm(key->key);
		assert(a < MAX_ALGORITHMS);

		if (key->is_public) {
			// public key creates a requirement for an algorithm
			algorithms[a].published = true;

			// need fully enabled ZSK and KSK for each algorithm
			if (key->is_active) {
				if (key->is_ksk) {
					algorithms[a].ksk_enabled = true;
				}
				if (key->is_zsk) {
					algorithms[a].zsk_enabled = true;
				}
			}
		}
	}

	/* Validate enabled algorithms */

	int enabled_count = 0;
	for (int a = 0; a < MAX_ALGORITHMS; a++) {
		if (!algorithms[a].published) {
			continue;
		}

		if (!algorithms[a].ksk_enabled || !algorithms[a].zsk_enabled) {
			return KNOT_DNSSEC_EMISSINGKEYTYPE;
		}

		enabled_count += 1;
	}

	if (enabled_count == 0) {
		return KNOT_DNSSEC_ENOKEY;
	}

	return KNOT_EOK;
}

/*!
 * \brief Log information about zone keys.
 */
static void log_key_info(const zone_key_t *key, const char *zone_name)
{
	assert(key);
	assert(zone_name);

	log_zone_str_info(zone_name, "DNSSEC, loaded key, tag %5d, "
			  "KSK %s, ZSK %s, public %s, active %s",
			  dnssec_key_get_keytag(key->key),
			  key->is_ksk ? "yes" : "no",
			  key->is_zsk ? "yes" : "no",
			  key->is_public ? "yes" : "no",
			  key->is_active ? "yes" : "no");
}

/*!
 * \brief Load zone keys from a key directory.
 */
int load_zone_keys(const char *keydir_name, const char *zone_name,
                   zone_keyset_t *keyset_ptr)
{
	if (!keydir_name || !zone_name || !keyset_ptr) {
		return KNOT_EINVAL;
	}

	zone_keyset_t keyset = {0};

	int r = dnssec_kasp_open_dir(keydir_name, &keyset.kasp);
	if (r != DNSSEC_EOK) {
		log_zone_str_error(zone_name, "DNSSEC, failed to open KASP (%s)",
		                   dnssec_strerror(r));
		return KNOT_ERROR;
	}

	r = dnssec_kasp_load_zone(keyset.kasp, zone_name, &keyset.kasp_zone);
	if (r != DNSSEC_EOK) {
		log_zone_str_error(zone_name, "DNSSEC, failed to get zone from KASP (%s)",
		                   dnssec_strerror(r));
		free_zone_keys(&keyset);
		return KNOT_ERROR;
	}

	dnssec_kasp_keyset_t *kasp_keys = dnssec_kasp_zone_get_keys(keyset.kasp_zone);
	keyset.count = dnssec_kasp_keyset_count(kasp_keys);
	if (keyset.count == 0) {
		log_zone_str_error(zone_name, "DNSSEC, no keys are available");
		free_zone_keys(&keyset);
		return KNOT_ERROR;
	}

	keyset.keys = calloc(keyset.count, sizeof(zone_key_t));
	if (!keyset.keys) {
		free_zone_keys(&keyset);
		return KNOT_ENOMEM;
	}

	for (size_t i = 0; i < keyset.count; i++) {
		dnssec_kasp_key_t *kasp_key = dnssec_kasp_keyset_at(kasp_keys, i);
		set_key(kasp_key, &keyset.keys[i]);
		log_key_info(&keyset.keys[i], zone_name);
	}

	r = check_keys_validity(&keyset);
	if (r != KNOT_EOK) {
		log_zone_str_error(zone_name, "DNSSEC, keys validation failed (%s)",
		                   knot_strerror(r));
		free_zone_keys(&keyset);
		return KNOT_ERROR;
	}


	r = load_private_keys(keydir_name, &keyset);
	if (r != KNOT_EOK) {
		free_zone_keys(&keyset);
		return r;
	}

	*keyset_ptr = keyset;
	return KNOT_EOK;
}

/*!
 * \brief Free structure with zone keys and associated DNSSEC contexts.
 */
void free_zone_keys(zone_keyset_t *keyset)
{
	if (!keyset) {
		return;
	}

	for (size_t i = 0; i < keyset->count; i++) {
		dnssec_sign_free(keyset->keys[i].ctx);
	}

	dnssec_kasp_zone_free(keyset->kasp_zone);
	dnssec_kasp_close(keyset->kasp);
	free(keyset->keys);

	memset(keyset, '\0', sizeof(*keyset));
}

/*!
 * \brief Get timestamp of the next key event.
 */
time_t knot_get_next_zone_key_event(const zone_keyset_t *keyset)
{
	time_t result = LONG_MAX;

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		if (key->next_event < result) {
			result = key->next_event;
		}
	}

	return result;
}
