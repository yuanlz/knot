#pragma once

#include <stdbool.h>
#include <ngtcp2/ngtcp2.h>

/*! \brief QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

typedef struct {
	/*! QUIC parameters. */
	const quic_params_t *params;
	/*! ngtcp2 (QUIC) setting. */
	ngtcp2_settings settings;
	/*! client secret */
	uint8_t static_secret[32];
	/*! QUIC state. */
	ngtcp2_conn *conn;
} quic_ctx_t;

int quic_ctx_init(quic_ctx_t *ctx, const quic_params_t *params);

int quic_ctx_connect(quic_ctx_t *ctx);