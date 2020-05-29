/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "contrib/macros.h"
#include "contrib/wire_ctx.h"
#include "knot/include/module.h"
#include "knot/conf/base.h"
#include "knot/conf/schema.h"
#include "knot/conf/conf.h"
#include "libknot/libknot.h"

#include <stdio.h>
#include <netinet/ip.h>

#define MOD_PREFIX		"\x06""prefix"

static int check_prefix(knotd_conf_check_args_t *args)
{
	if (strchr((const char *)args->data, '.') != NULL) {
		args->err_str = "dot '.' is not allowed";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

const yp_item_t probe_conf[] = {
	{ MOD_PREFIX,      YP_TSTR, YP_VSTR = { "kprobe-" },           YP_FNONE, { check_prefix } },
	{ NULL }
};

int probe_conf_check(knotd_conf_check_args_t *args)
{
	// Check type.
	knotd_conf_t type = knotd_conf_check_item(args, MOD_PREFIX);
	if (strlen(type.single.string) > KNOT_PROBE_PREFIX_MAXSIZE) {
		args->err_str = "prefix is too long";
		return KNOT_EINVAL;
	}
	return KNOT_EOK;
}

typedef struct probe_ctx {
	knot_probe_channel_t *probes;
	size_t probe_count;
} probe_ctx_t;


static int ss_to_addr(addr_t *addr, const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in *)ss;
		memcpy(addr->addr, &sa->sin_addr, sizeof(sa->sin_addr));
		addr->family = ss->ss_family;
		addr->port = sa->sin_port;
		return KNOT_EOK;
	}
	else if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ss;
		memcpy(addr->addr, &sa->sin6_addr, sizeof(sa->sin6_addr));
		addr->family = sa->sin6_family;
		addr->port = sa->sin6_port;
		return KNOT_EOK;
	}
	return KNOT_EINVAL;
}

static knotd_state_t transfer(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata);

	unsigned tid = qdata->params->thread_id;
	probe_ctx_t *p = knotd_mod_ctx(mod);
	knot_probe_channel_t *probe = &(p->probes[tid % p->probe_count]);
	
	const struct sockaddr_storage *src = qdata->params->remote;
	const struct sockaddr_storage *dst = qdata->params->server;
	
	knot_probe_datagram_t d;
	
	ss_to_addr(&d.src, src);
	ss_to_addr(&d.dst, dst);

	memcpy(d.query_wire, qdata->query->wire, sizeof(d.query_wire));
	memcpy(d.response_wire, pkt->wire, sizeof(d.response_wire));

	knot_probe_channel_send(probe, (uint8_t *)&d, sizeof(d), 0);

	return state;
}

int probe_load(knotd_mod_t *mod)
{
	conf_val_t val = conf_get(conf(), C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&val, NULL);
	if (!rundir) {
		return KNOT_EINVAL;
	}

	knotd_conf_t mod_conf = knotd_conf_mod(mod, MOD_PREFIX);
	char prefix[KNOT_PROBE_PREFIX_MAXSIZE + 1];
	char *sep = rundir[strlen(rundir) - 1] != '/' ? "/" : "";
	if (snprintf(prefix, KNOT_PROBE_PREFIX_MAXSIZE, "%s%s%s", rundir, sep, mod_conf.single.string) > KNOT_PROBE_PREFIX_MAXSIZE) {
		free(rundir);
		return KNOT_EINVAL;
	}
	free(rundir);

	probe_ctx_t *p = (probe_ctx_t *)calloc(1, sizeof(*p));
	if (!p) {
		return KNOT_ENOMEM;
	}

	if ((p->probe_count = conf()->cache.srv_bg_threads) == 0) {
		free(p);
		return KNOT_EINVAL;
	}

	p->probes = (knot_probe_channel_t *)calloc(p->probe_count, sizeof(knot_probe_channel_t));
	if (!p->probes) {
		free(p);
		return KNOT_ENOMEM;
	}
	int ret;
	for (knot_probe_channel_t *it = p->probes; it < &p->probes[p->probe_count]; ++it) {
		if (unlikely((ret = knot_probe_channel_init(it, prefix, (it - p->probes))) != KNOT_EOK)) {
			for (--it; it >= p->probes; --it) { // On error close all previous sockets
				knot_probe_channel_close(it);
			}
			free(p->probes);
			free(p);
			return ret;
		}
	}

	knotd_mod_ctx_set(mod, p);

	return knotd_mod_hook(mod, KNOTD_STAGE_END, transfer);
}

void probe_unload(knotd_mod_t *mod)
{
	probe_ctx_t *p = (probe_ctx_t *)knotd_mod_ctx(mod);
	for (int i = 0; i < p->probe_count; ++i) {
		knot_probe_channel_close(&p->probes[i]);
	}
	free(p->probes);
	free(knotd_mod_ctx(mod));
	knotd_mod_ctx_set(mod, NULL);
}

KNOTD_MOD_API(probe, KNOTD_MOD_FLAG_SCOPE_GLOBAL | KNOTD_MOD_FLAG_OPT_CONF,
              probe_load, probe_unload, probe_conf, probe_conf_check);