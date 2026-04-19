#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>

#include "lab.h"
#include "mac.h"

/*
 * Mỗi gói (một buffer trong UMEM dùng chung, không copy payload):
 *   BPF XDP redirect -> AF_XDP RX (core 0 = LAN, core 11 = WAN)
 *   -> ring -> core 3 sửa Ethernet MAC tại chỗ
 *   -> ring -> AF_XDP TX zero-copy -> NIC đích (WAN hoặc LAN tuỳ hướng)
 *
 * Debug stderr:
 *   Mỗi LAB_DEBUG_MS ms (mặc định 1000): một dòng thống kê L->W và W->L.
 *   LAB_HEX_PKTS=N: in N gói đầu (hex 48 byte) sau rewrite->WAN (core 3)
 *   và ngay trước ZC TX ra WAN (core 11).
 */

static void setaffinity(unsigned int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static void dbg_hex_pkt(const char *tag, unsigned cpu, const uint8_t *pkt,
			uint32_t len)
{
	unsigned n = len < 48u ? len : 48u;
	unsigned i;

	fprintf(stderr, "[lab] %s (cpu%u) len=%u:", tag, cpu, len);
	for (i = 0; i < n; i++)
		fprintf(stderr, " %02x", pkt[i]);
	if (len > n)
		fprintf(stderr, " ...");
	fprintf(stderr, "\n");
	fflush(stderr);
}

static void rewrite_eth(struct lab_pair *zc, uint64_t addr, enum lab_dir d)
{
	uint8_t *pkt = lab_ptr(zc, addr);
	static const uint8_t wan_peer[] = { MAC_WAN_PEER };
	static const uint8_t mac_enp4[] = { MAC_ENP4S0 };
	static const uint8_t peer_loc[] = { MAC_PEER_LOCAL };
	static const uint8_t mac_enp7[] = { MAC_ENP7S0 };

	if (d == LAB_DIR_TO_WAN) {
		memcpy(pkt, wan_peer, ETH_ALEN);
		memcpy(pkt + ETH_ALEN, mac_enp4, ETH_ALEN);
	} else {
		memcpy(pkt, peer_loc, ETH_ALEN);
		memcpy(pkt + ETH_ALEN, mac_enp7, ETH_ALEN);
	}
}

static void *dbg_thread(void *arg)
{
	struct lab_ctx *c = arg;
	unsigned ms = 1000;
	const char *e = getenv("LAB_DEBUG_MS");

	if (e) {
		int v = atoi(e);
		if (v >= 200)
			ms = (unsigned)v;
	}

	while (!c->stop) {
		struct timespec ts = { .tv_sec = ms / 1000,
				       .tv_nsec = (long)(ms % 1000) * 1000000L };
		(void)nanosleep(&ts, NULL);
		if (c->stop)
			break;
		{
			struct lab_pkt_stats s = c->st;
			fprintf(stderr,
				"[lab] L->W afxdp_rx=%" PRIu64 " ing_enq=%" PRIu64
				" mid_rw=%" PRIu64 " w2w_enq=%" PRIu64
				" wan_pop=%" PRIu64 " tx_ok=%" PRIu64 " tx_busy=%" PRIu64 "\n",
				s.loc_afxdp_rx, s.ing_to_mid_enq, s.mid_ing_to_wan,
				s.w_to_wan_enq, s.wan_w2w_pop, s.wan_zc_tx_ok,
				s.wan_zc_tx_busy);
			fprintf(stderr,
				"[lab] W->L afxdp_rx=%" PRIu64 " wan_mid_enq=%" PRIu64
				" mid_rl=%" PRIu64 " w2l_enq=%" PRIu64
				" loc_pop=%" PRIu64 " tx_ok=%" PRIu64 " tx_busy=%" PRIu64 "\n",
				s.wan_afxdp_rx, s.wan_to_mid_enq, s.mid_wan_to_loc,
				s.w_to_loc_enq, s.loc_w2l_pop, s.loc_zc_tx_ok,
				s.loc_zc_tx_busy);
			fflush(stderr);
		}
	}
	return NULL;
}

static void *loc_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	uint32_t lens[LAB_RECV_BATCH];
	uint64_t addrs[LAB_RECV_BATCH];
	struct lab_job j;
	int n, i;

	setaffinity(LAB_CPU_LOC);
	for (;;) {
		if (ctx->stop)
			break;
		while (lab_ring_try_pop(&ctx->w_to_loc, &j) == 0) {
			__sync_fetch_and_add(&ctx->st.loc_w2l_pop, 1);
			for (;;) {
				if (lab_tx_loc(&ctx->zc, j.umem_addr, j.len) == 0) {
					__sync_fetch_and_add(&ctx->st.loc_zc_tx_ok, 1);
					break;
				}
				__sync_fetch_and_add(&ctx->st.loc_zc_tx_busy, 1);
				sched_yield();
			}
		}
		n = lab_recv_loc(&ctx->zc, lens, addrs, LAB_RECV_BATCH);
		for (i = 0; i < n; i++) {
			__sync_fetch_and_add(&ctx->st.loc_afxdp_rx, 1);
			j.umem_addr = addrs[i];
			j.len = lens[i];
			if (lab_ring_push_retry(&ctx->ing_to_mid, &j, &ctx->stop))
				break;
			__sync_fetch_and_add(&ctx->st.ing_to_mid_enq, 1);
		}
		if (!n)
			sched_yield();
	}
	return NULL;
}

static void *wan_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	uint32_t lens[LAB_RECV_BATCH];
	uint64_t addrs[LAB_RECV_BATCH];
	struct lab_job j;
	int n, i;

	setaffinity(LAB_CPU_WAN);
	for (;;) {
		if (ctx->stop)
			break;
		while (lab_ring_try_pop(&ctx->w_to_wan, &j) == 0) {
			__sync_fetch_and_add(&ctx->st.wan_w2w_pop, 1);
			if (ctx->dbg_hex_wan_tx) {
				unsigned left = __sync_fetch_and_sub(&ctx->dbg_hex_wan_tx, 1);

				if (left > 0) {
					const uint8_t *pkt =
						lab_ptr(&ctx->zc, j.umem_addr);

					dbg_hex_pkt("ETH before ZC TX->WAN", LAB_CPU_WAN,
						    pkt, j.len);
				}
			}
			for (;;) {
				if (lab_tx_wan(&ctx->zc, j.umem_addr, j.len) == 0) {
					__sync_fetch_and_add(&ctx->st.wan_zc_tx_ok, 1);
					break;
				}
				__sync_fetch_and_add(&ctx->st.wan_zc_tx_busy, 1);
				sched_yield();
			}
		}
		n = lab_recv_wan(&ctx->zc, lens, addrs, LAB_RECV_BATCH);
		for (i = 0; i < n; i++) {
			__sync_fetch_and_add(&ctx->st.wan_afxdp_rx, 1);
			j.umem_addr = addrs[i];
			j.len = lens[i];
			if (lab_ring_push_retry(&ctx->wan_to_mid, &j, &ctx->stop))
				break;
			__sync_fetch_and_add(&ctx->st.wan_to_mid_enq, 1);
		}
		if (!n)
			sched_yield();
	}
	return NULL;
}

static void *mid_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	struct lab_job j;

	setaffinity(LAB_CPU_MID);
	for (;;) {
		if (ctx->stop)
			break;
		if (lab_ring_try_pop(&ctx->ing_to_mid, &j) == 0) {
			__sync_fetch_and_add(&ctx->st.mid_ing_to_wan, 1);
			rewrite_eth(&ctx->zc, j.umem_addr, LAB_DIR_TO_WAN);
			if (ctx->dbg_hex_wan_mid) {
				unsigned left =
					__sync_fetch_and_sub(&ctx->dbg_hex_wan_mid, 1);

				if (left > 0) {
					const uint8_t *pkt =
						lab_ptr(&ctx->zc, j.umem_addr);

					dbg_hex_pkt("ETH after rewrite->WAN", LAB_CPU_MID,
						    pkt, j.len);
				}
			}
			if (lab_ring_push_retry(&ctx->w_to_wan, &j, &ctx->stop))
				break;
			__sync_fetch_and_add(&ctx->st.w_to_wan_enq, 1);
			continue;
		}
		if (lab_ring_try_pop(&ctx->wan_to_mid, &j) == 0) {
			__sync_fetch_and_add(&ctx->st.mid_wan_to_loc, 1);
			rewrite_eth(&ctx->zc, j.umem_addr, LAB_DIR_TO_LOC);
			if (lab_ring_push_retry(&ctx->w_to_loc, &j, &ctx->stop))
				break;
			__sync_fetch_and_add(&ctx->st.w_to_loc_enq, 1);
			continue;
		}
		sched_yield();
	}
	return NULL;
}

int lab_run(struct lab_ctx *ctx, const char *loc_if, const char *wan_if,
	    const char *bpf_loc, const char *bpf_wan)
{
	const char *hex_env;
	unsigned hex_n = 3;

	memset(ctx, 0, sizeof(*ctx));
	if (lab_pair_open(&ctx->zc, loc_if, wan_if, bpf_loc, bpf_wan))
		return -1;
	if (lab_ring_init(&ctx->ing_to_mid, LAB_RING) ||
	    lab_ring_init(&ctx->wan_to_mid, LAB_RING) ||
	    lab_ring_init(&ctx->w_to_wan, LAB_RING) ||
	    lab_ring_init(&ctx->w_to_loc, LAB_RING)) {
		lab_pair_close(&ctx->zc);
		return -1;
	}
	ctx->stop = 0;
	hex_env = getenv("LAB_HEX_PKTS");
	if (hex_env)
		hex_n = (unsigned)strtoul(hex_env, NULL, 10);
	ctx->dbg_hex_wan_mid = hex_n;
	ctx->dbg_hex_wan_tx = hex_n;

	if (pthread_create(&ctx->th_loc, NULL, loc_worker, ctx))
		goto err_th;
	if (pthread_create(&ctx->th_mid, NULL, mid_worker, ctx))
		goto err_mid;
	if (pthread_create(&ctx->th_wan, NULL, wan_worker, ctx))
		goto err_wan;
	fprintf(stderr,
		"[lab] debug: stats every LAB_DEBUG_MS (default 1000); "
		"LAB_HEX_PKTS=%u sample hex\n",
		hex_n);
	fflush(stderr);
	if (pthread_create(&ctx->th_dbg, NULL, dbg_thread, ctx))
		goto err_dbg;
	return 0;

err_dbg:
	ctx->stop = 1;
	lab_ring_wake_all(&ctx->ing_to_mid);
	lab_ring_wake_all(&ctx->wan_to_mid);
	lab_ring_wake_all(&ctx->w_to_wan);
	lab_ring_wake_all(&ctx->w_to_loc);
	pthread_join(ctx->th_wan, NULL);
	pthread_join(ctx->th_mid, NULL);
	pthread_join(ctx->th_loc, NULL);
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
	return -1;

err_wan:
	ctx->stop = 1;
	lab_ring_wake_all(&ctx->ing_to_mid);
	lab_ring_wake_all(&ctx->wan_to_mid);
	lab_ring_wake_all(&ctx->w_to_wan);
	lab_ring_wake_all(&ctx->w_to_loc);
	pthread_join(ctx->th_mid, NULL);
	pthread_join(ctx->th_loc, NULL);
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
	return -1;

err_mid:
	ctx->stop = 1;
	lab_ring_wake_all(&ctx->ing_to_mid);
	lab_ring_wake_all(&ctx->wan_to_mid);
	lab_ring_wake_all(&ctx->w_to_wan);
	lab_ring_wake_all(&ctx->w_to_loc);
	pthread_join(ctx->th_loc, NULL);
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
	return -1;

err_th:
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
	return -1;
}

void lab_ctx_stop(struct lab_ctx *ctx)
{
	ctx->stop = 1;
	lab_ring_wake_all(&ctx->ing_to_mid);
	lab_ring_wake_all(&ctx->wan_to_mid);
	lab_ring_wake_all(&ctx->w_to_wan);
	lab_ring_wake_all(&ctx->w_to_loc);
}

void lab_ctx_join(struct lab_ctx *ctx)
{
	pthread_join(ctx->th_loc, NULL);
	pthread_join(ctx->th_mid, NULL);
	pthread_join(ctx->th_wan, NULL);
	pthread_join(ctx->th_dbg, NULL);
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
}
