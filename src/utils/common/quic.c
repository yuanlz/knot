#include "utils/common/quic.h"

#include "assert.h"
#include "libknot/errcode.h"
#include "libdnssec/random.h"

#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

static int generate_cid(ngtcp2_cid *cid, unsigned len)
{
	if (cid == NULL || len > NGTCP2_MAX_CIDLEN) {
		return KNOT_EINVAL;
	}
    
	int ret = dnssec_random_buffer(cid->data, len);
	if (ret != KNOT_EOK) {
		return ret;
	}
	cid->datalen = len;
	return KNOT_EOK;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                                 size_t cidlen, void *user_data)
{
	quic_ctx_t *ctx = user_data;

	generate_cid(cid, cidlen);
	ngtcp2_crypto_md md = {0};
	if (ngtcp2_crypto_generate_stateless_reset_token(
	        token, &md, ctx->static_secret, sizeof(ctx->static_secret), cid
		) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int generate_secret(uint8_t *secret, size_t secretlen)
{
	// const size_t md_size = 32;
	// uint8_t rand[16];
	// uint8_t md[md_size];

	assert(secretlen == secretlen);

	// dnssec_random_buffer(rand, sizeof(rand));

	// void *ctx = NULL;
	// gnutls_digest_init_func(GNUTLS_DIG_SHA256, &ctx);
	// if (ctx == NULL) {
	// 	return KNOT_ENOMEM;
	// }

	// if (!gnutls_digest_hash_func(ctx, rand, sizeof(rand)) ||
	//     !gnutls_digest_output_func(ctx, md, md_size))
	// {
	// 	gnutls_digest_deinit_func(ctx);
	// 	return -1;
	// }

	// gnutls_digest_deinit_func(ctx);
	// memcpy(secret, md, md_size);
	dnssec_random_buffer(secret, secretlen);
	return KNOT_EOK;
}

static int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                            uint64_t offset, const uint8_t *data, size_t datalen,
                            void *user_data)
{
	quic_ctx_t *ctx = user_data;

	if (ngtcp2_crypto_read_write_crypto_data(ctx->conn, crypto_level, data, datalen) != 0) {
		int err;
		if (err = ngtcp2_conn_get_tls_error(conn)) {
			return err;
		}
		return NGTCP2_ERR_CRYPTO;
	}

	return 0;
}

int quic_ctx_init(quic_ctx_t *ctx, const quic_params_t *params)
{
	ngtcp2_settings_default(&ctx->settings);
	// settings.max_udp_payload_size = max_pktlen_;
	// settings.cc_algo = config.cc == "cubic" ? NGTCP2_CC_ALGO_CUBIC : NGTCP2_CC_ALGO_RENO;
	// settings.initial_ts = util::timestamp(loop_);
	// settings.initial_rtt = config.initial_rtt;
	// settings.max_window = config.max_window;
	// settings.max_stream_window = config.max_stream_window;

	generate_secret(ctx->static_secret, sizeof(ctx->static_secret));	
	ctx->params = params;
	return KNOT_EOK;
}

int quic_ctx_connect(quic_ctx_t *ctx)
{
	ngtcp2_cid scid, dcid;
	if (generate_cid(&scid, 17) || generate_cid(&dcid, 18)) {
		return KNOT_EINVAL;
	}
	const ngtcp2_callbacks *callbacks = {
		ngtcp2_crypto_client_initial_cb,
		NULL, // recv_client_initial
		recv_crypto_data,
		NULL, // ::handshake_completed,
		NULL, // recv_version_negotiation
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask,
		NULL, // ::recv_stream_data,
		NULL, // acked_crypto_offset,
		NULL, // ::acked_stream_data_offset,
		NULL, // stream_open
		NULL, // stream_close,
		NULL, // recv_stateless_reset
		ngtcp2_crypto_recv_retry_cb,
		NULL, // extend_max_streams_bidi,
		NULL, // extend_max_streams_uni
		rand,
		get_new_connection_id,
		NULL, // remove_connection_id,
		ngtcp2_crypto_update_key_cb, // ::update_key,
		NULL, // path_validation,
		NULL, // ::select_preferred_address,
		NULL, // stream_reset,
		NULL, // extend_max_remote_streams_bidi,
		NULL, // extend_max_remote_streams_uni,
		NULL, // ::extend_max_stream_data,
		NULL, // dcid_status
		NULL, // ::handshake_confirmed,
		NULL, // ::recv_new_token,
		ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
	};
	ngtcp2_conn_client_new(&ctx->conn, &dcid, &scid, NULL, 0, callbacks, &ctx->settings, NULL, NULL);
	return KNOT_EOK;
}