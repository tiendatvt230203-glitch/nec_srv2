#ifndef LAB_H
#define LAB_H

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <xdp/xsk.h>

struct bpf_object;

#define LAB_RING       1024u
#define LAB_FRAME      2048u
#define LAB_RING_CAP   4096u
#define LAB_RECV_BATCH 32
#define LAB_CPU_LOC    0u
#define LAB_CPU_MID    3u
#define LAB_CPU_WAN    11u

enum lab_dir {
	LAB_DIR_TO_WAN = 0,
	LAB_DIR_TO_LOC = 1,
};

struct lab_job {
	uint64_t umem_addr;
	uint32_t len;
};

struct lab_ring {
	pthread_mutex_t mu;
	pthread_cond_t nonempty;
	pthread_cond_t nonfull;
	struct lab_job *buf;
	uint32_t cap;
	uint32_t head;
	uint32_t tail;
	uint32_t count;
};

struct lab_zc_port {
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	int ifindex;
};

struct lab_pair {
	void *bufs;
	size_t bufsize;
	uint32_t frame_size;
	struct xsk_umem *umem;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct lab_zc_port loc;
	struct lab_zc_port wan;
	struct bpf_object *bpf_loc;
	struct bpf_object *bpf_wan;
	uint8_t xdp_loc_on;
	uint8_t xdp_wan_on;
	uint32_t n_frames;
	uint64_t *frame_stack;
	uint32_t stack_nt;
	uint32_t stack_cap;
	pthread_mutex_t pool_mu;
	pthread_mutex_t umem_fq_mu;
	pthread_mutex_t umem_cq_tx_mu;
};

int lab_ring_init(struct lab_ring *r, uint32_t cap);
void lab_ring_destroy(struct lab_ring *r);
int lab_ring_try_pop(struct lab_ring *r, struct lab_job *j);
void lab_ring_wake_all(struct lab_ring *r);
int lab_ring_push_retry(struct lab_ring *r, const struct lab_job *j, volatile sig_atomic_t *stop);

int lab_pair_open(struct lab_pair *p, const char *loc_if, const char *wan_if,
		  const char *bpf_loc_o, const char *bpf_wan_o);
void lab_pair_close(struct lab_pair *p);

int lab_recv_loc(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max);
int lab_recv_wan(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max);
int lab_tx_loc(struct lab_pair *p, uint64_t addr, uint32_t len);
int lab_tx_wan(struct lab_pair *p, uint64_t addr, uint32_t len);

void *lab_ptr(struct lab_pair *p, uint64_t addr);

/*
 * Counters for stderr debug (see threads.c). Updated with __sync_fetch_and_add.
 * LAN->WAN: loc_afxdp_rx -> ing_to_mid -> mid_ing_to_wan -> w_to_wan -> wan_zc_tx_*.
 */
struct lab_pkt_stats {
	uint64_t loc_afxdp_rx;
	uint64_t ing_to_mid_enq;
	uint64_t mid_ing_to_wan;
	uint64_t w_to_wan_enq;
	uint64_t wan_w2w_pop;
	uint64_t wan_zc_tx_ok;
	uint64_t wan_zc_tx_busy;
	uint64_t wan_afxdp_rx;
	uint64_t wan_to_mid_enq;
	uint64_t mid_wan_to_loc;
	uint64_t w_to_loc_enq;
	uint64_t loc_w2l_pop;
	uint64_t loc_zc_tx_ok;
	uint64_t loc_zc_tx_busy;
};

struct lab_ctx {
	volatile sig_atomic_t stop;
	struct lab_pair zc;
	struct lab_ring ing_to_mid;
	struct lab_ring wan_to_mid;
	struct lab_ring w_to_wan;
	struct lab_ring w_to_loc;
	pthread_t th_loc;
	pthread_t th_mid;
	pthread_t th_wan;
	pthread_t th_dbg;
	struct lab_pkt_stats st;
	uint32_t dbg_hex_wan_mid;
	uint32_t dbg_hex_wan_tx;
};

int lab_run(struct lab_ctx *ctx, const char *loc_if, const char *wan_if,
	    const char *bpf_loc, const char *bpf_wan);
void lab_ctx_stop(struct lab_ctx *ctx);
void lab_ctx_join(struct lab_ctx *ctx);

#endif
