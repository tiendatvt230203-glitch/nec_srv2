#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>

#include "lab.h"
#include "mac.h"

static void st_add(volatile uint64_t *c, uint64_t n)
{
	__sync_fetch_and_add(c, n);
}

static void *stats_thread(void *arg)
{
	struct lab_ctx *c = arg;

	fprintf(stderr,
		"[nec] NEC_STATS on (stderr every ~2s). rx_* = AF_XDP RX pkts, "
		"tx_* = TX pkts, push_* / mid>* = handoff, q *= ring depth\n");
	fflush(stderr);
	while (!c->stop) {
		fprintf(stderr,
			"[nec] rx_loc=%llu rx_wan=%llu tx_loc=%llu tx_wan=%llu "
			"push_ing=%llu push_wan_mid=%llu mid>wan=%llu mid>loc=%llu | "
			"q ing=%u wan_mid=%u w_wan=%u w_loc=%u\n",
			(unsigned long long)c->cnt_rx_loc,
			(unsigned long long)c->cnt_rx_wan,
			(unsigned long long)c->cnt_tx_loc,
			(unsigned long long)c->cnt_tx_wan,
			(unsigned long long)c->cnt_push_ing,
			(unsigned long long)c->cnt_push_wan_mid,
			(unsigned long long)c->cnt_mid_wan,
			(unsigned long long)c->cnt_mid_loc,
			(unsigned)lab_ring_count(&c->ing_to_mid),
			(unsigned)lab_ring_count(&c->wan_to_mid),
			(unsigned)lab_ring_count(&c->w_to_wan),
			(unsigned)lab_ring_count(&c->w_to_loc));
		fflush(stderr);
		for (unsigned k = 0; k < 200 && !c->stop; k++)
			usleep(10000);
	}
	return NULL;
}

static void setaffinity(unsigned int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
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

static void *loc_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	void *ptrs[LAB_RECV_BATCH];
	uint32_t lens[LAB_RECV_BATCH];
	uint64_t addrs[LAB_RECV_BATCH];
	struct lab_job j;
	int n, i;

	setaffinity(LAB_CPU_LOC);
	for (;;) {
		if (ctx->stop)
			break;
		while (lab_ring_try_pop(&ctx->w_to_loc, &j) == 0) {
			if (lab_tx_loc(&ctx->zc, j.umem_addr, j.len)) {
				sched_yield();
				continue;
			}
			st_add(&ctx->cnt_tx_loc, 1);
		}
		n = lab_recv_loc(&ctx->zc, ptrs, lens, addrs, LAB_RECV_BATCH);
		if (n > 0)
			st_add(&ctx->cnt_rx_loc, (uint64_t)n);
		for (i = 0; i < n; i++) {
			j.umem_addr = addrs[i];
			j.len = lens[i];
			j.dir = LAB_DIR_TO_WAN;
			(void)ptrs[i];
			if (lab_ring_push_retry(&ctx->ing_to_mid, &j, &ctx->stop))
				break;
			st_add(&ctx->cnt_push_ing, 1);
		}
		if (!n)
			sched_yield();
	}
	return NULL;
}

static void *wan_worker(void *arg)
{
	struct lab_ctx *ctx = arg;
	void *ptrs[LAB_RECV_BATCH];
	uint32_t lens[LAB_RECV_BATCH];
	uint64_t addrs[LAB_RECV_BATCH];
	struct lab_job j;
	int n, i;

	setaffinity(LAB_CPU_WAN);
	for (;;) {
		if (ctx->stop)
			break;
		while (lab_ring_try_pop(&ctx->w_to_wan, &j) == 0) {
			if (lab_tx_wan(&ctx->zc, j.umem_addr, j.len)) {
				sched_yield();
				continue;
			}
			st_add(&ctx->cnt_tx_wan, 1);
		}
		n = lab_recv_wan(&ctx->zc, ptrs, lens, addrs, LAB_RECV_BATCH);
		if (n > 0)
			st_add(&ctx->cnt_rx_wan, (uint64_t)n);
		for (i = 0; i < n; i++) {
			j.umem_addr = addrs[i];
			j.len = lens[i];
			j.dir = LAB_DIR_TO_LOC;
			(void)ptrs[i];
			if (lab_ring_push_retry(&ctx->wan_to_mid, &j, &ctx->stop))
				break;
			st_add(&ctx->cnt_push_wan_mid, 1);
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
			rewrite_eth(&ctx->zc, j.umem_addr, LAB_DIR_TO_WAN);
			if (lab_ring_push_retry(&ctx->w_to_wan, &j, &ctx->stop))
				break;
			st_add(&ctx->cnt_mid_wan, 1);
			continue;
		}
		if (lab_ring_try_pop(&ctx->wan_to_mid, &j) == 0) {
			rewrite_eth(&ctx->zc, j.umem_addr, LAB_DIR_TO_LOC);
			if (lab_ring_push_retry(&ctx->w_to_loc, &j, &ctx->stop))
				break;
			st_add(&ctx->cnt_mid_loc, 1);
			continue;
		}
		sched_yield();
	}
	return NULL;
}

int lab_run(struct lab_ctx *ctx, const char *loc_if, const char *wan_if,
	    const char *bpf_loc, const char *bpf_wan)
{
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
	if (pthread_create(&ctx->th_loc, NULL, loc_worker, ctx))
		goto err_th;
	if (pthread_create(&ctx->th_mid, NULL, mid_worker, ctx))
		goto err_mid;
	if (pthread_create(&ctx->th_wan, NULL, wan_worker, ctx))
		goto err_wan;
	{
		const char *st = getenv("NEC_STATS");

		if (st && st[0] != '0') {
			if (pthread_create(&ctx->th_stats, NULL, stats_thread,
					   ctx) == 0)
				ctx->stats_on = 1;
		}
	}
	return 0;

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
	if (ctx->stats_on) {
		pthread_join(ctx->th_stats, NULL);
		ctx->stats_on = 0;
	}
	pthread_join(ctx->th_loc, NULL);
	pthread_join(ctx->th_mid, NULL);
	pthread_join(ctx->th_wan, NULL);
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
}
