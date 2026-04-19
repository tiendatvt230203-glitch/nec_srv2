#ifndef LAB_H
#define LAB_H

#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <xdp/xsk.h>

struct bpf_object;
struct bpf_link;

#define LAB_RING       1024u
#define LAB_FRAME      2048u
#define LAB_RING_CAP   4096u
#define LAB_RECV_BATCH 32
#define LAB_CPU_LOC    0u
#define LAB_CPU_MID    3u
#define LAB_CPU_WAN    11u

#define LAB_IF_LOC "enp7s0"
#define LAB_IF_WAN "enp4s0"

enum lab_dir {
	LAB_DIR_TO_WAN = 0,
	LAB_DIR_TO_LOC = 1,
};

struct lab_job {
	uint64_t umem_addr;
	uint32_t len;
	uint8_t dir;
	uint8_t pad[3];
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
	char ifname[IF_NAMESIZE];
};

struct lab_pair {
	void *bufs;
	size_t bufsize;
	uint32_t ring_size;
	uint32_t frame_size;
	struct xsk_umem *umem;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct lab_zc_port loc;
	struct lab_zc_port wan;
	struct bpf_object *bpf_loc;
	struct bpf_object *bpf_wan;
	struct bpf_link *lnk_loc;
	struct bpf_link *lnk_wan;
	int xsks_map_fd;
	int wan_xsks_map_fd;
	uint32_t n_frames;
	uint64_t *frame_stack;
	uint32_t stack_nt;
	uint32_t stack_cap;
	pthread_mutex_t pool_mu;
};

int lab_ring_init(struct lab_ring *r, uint32_t cap);
void lab_ring_destroy(struct lab_ring *r);
int lab_ring_try_push(struct lab_ring *r, const struct lab_job *j);
int lab_ring_try_pop(struct lab_ring *r, struct lab_job *j);
void lab_ring_wake_all(struct lab_ring *r);
int lab_ring_push_retry(struct lab_ring *r, const struct lab_job *j, volatile sig_atomic_t *stop);

int lab_pair_open(struct lab_pair *p, const char *loc_if, const char *wan_if,
		  const char *bpf_loc_o, const char *bpf_wan_o);
void lab_pair_close(struct lab_pair *p);

int lab_recv_loc(struct lab_pair *p, void **ptrs, uint32_t *lens, uint64_t *addrs, int max);
int lab_recv_wan(struct lab_pair *p, void **ptrs, uint32_t *lens, uint64_t *addrs, int max);
int lab_tx_loc(struct lab_pair *p, uint64_t addr, uint32_t len);
int lab_tx_wan(struct lab_pair *p, uint64_t addr, uint32_t len);

void *lab_ptr(struct lab_pair *p, uint64_t addr);

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
};

int lab_run(struct lab_ctx *ctx, const char *loc_if, const char *wan_if,
	    const char *bpf_loc, const char *bpf_wan);
void lab_ctx_stop(struct lab_ctx *ctx);
void lab_ctx_join(struct lab_ctx *ctx);

#endif
