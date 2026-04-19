#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>

#include "lab.h"
#include "mac.h"

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
			if (lab_tx_loc(&ctx->zc, j.umem_addr, j.len))
				sched_yield();
		}
		n = lab_recv_loc(&ctx->zc, ptrs, lens, addrs, LAB_RECV_BATCH);
		for (i = 0; i < n; i++) {
			j.umem_addr = addrs[i];
			j.len = lens[i];
			j.dir = LAB_DIR_TO_WAN;
			(void)ptrs[i];
			if (lab_ring_push_retry(&ctx->ing_to_mid, &j, &ctx->stop))
				break;
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
			if (lab_tx_wan(&ctx->zc, j.umem_addr, j.len))
				sched_yield();
		}
		n = lab_recv_wan(&ctx->zc, ptrs, lens, addrs, LAB_RECV_BATCH);
		for (i = 0; i < n; i++) {
			j.umem_addr = addrs[i];
			j.len = lens[i];
			j.dir = LAB_DIR_TO_LOC;
			(void)ptrs[i];
			if (lab_ring_push_retry(&ctx->wan_to_mid, &j, &ctx->stop))
				break;
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
			continue;
		}
		if (lab_ring_try_pop(&ctx->wan_to_mid, &j) == 0) {
			rewrite_eth(&ctx->zc, j.umem_addr, LAB_DIR_TO_LOC);
			if (lab_ring_push_retry(&ctx->w_to_loc, &j, &ctx->stop))
				break;
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
	pthread_join(ctx->th_loc, NULL);
	pthread_join(ctx->th_mid, NULL);
	pthread_join(ctx->th_wan, NULL);
	lab_ring_destroy(&ctx->ing_to_mid);
	lab_ring_destroy(&ctx->wan_to_mid);
	lab_ring_destroy(&ctx->w_to_wan);
	lab_ring_destroy(&ctx->w_to_loc);
	lab_pair_close(&ctx->zc);
}
