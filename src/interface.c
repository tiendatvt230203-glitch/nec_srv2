#include <errno.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#include "lab.h"

static int lab_xskmap_bind(struct xsk_socket *xsk, int map_fd)
{
	int key = 0;
	int xfd;
	int err;

	if (!xsk || map_fd < 0)
		return -1;
	xfd = xsk_socket__fd(xsk);
	if (xfd < 0)
		return -1;
	err = xsk_socket__update_xskmap(xsk, map_fd);
	if (err)
		err = bpf_map_update_elem(map_fd, &key, &xfd, BPF_ANY);
	return err;
}

static int pool_pop(struct lab_pair *p, uint64_t *a)
{
	for (;;) {
		pthread_mutex_lock(&p->pool_mu);
		if (p->stack_nt > 0) {
			*a = p->frame_stack[--p->stack_nt];
			pthread_mutex_unlock(&p->pool_mu);
			return 0;
		}
		pthread_mutex_unlock(&p->pool_mu);
		sched_yield();
	}
}

static void pool_push(struct lab_pair *p, uint64_t a)
{
	for (;;) {
		pthread_mutex_lock(&p->pool_mu);
		if (p->stack_nt < p->stack_cap) {
			p->frame_stack[p->stack_nt++] = a;
			pthread_mutex_unlock(&p->pool_mu);
			return;
		}
		pthread_mutex_unlock(&p->pool_mu);
		sched_yield();
	}
}

static void lab_complete_cq(struct lab_pair *p, unsigned int batch)
{
	uint32_t idx;
	unsigned int got = xsk_ring_cons__peek(&p->umem_cq, batch, &idx);

	if (!got)
		return;

	for (unsigned int i = 0; i < got; i++) {
		uint64_t a = *xsk_ring_cons__comp_addr(&p->umem_cq, idx++);

		pool_push(p, a);
	}
	xsk_ring_cons__release(&p->umem_cq, got);
}

int lab_ring_init(struct lab_ring *r, uint32_t cap)
{
	memset(r, 0, sizeof(*r));
	r->cap = cap;
	r->buf = calloc(cap, sizeof(struct lab_job));
	if (!r->buf)
		return -1;
	if (pthread_mutex_init(&r->mu, NULL))
		goto err_buf;
	if (pthread_cond_init(&r->nonempty, NULL))
		goto err_mu;
	if (pthread_cond_init(&r->nonfull, NULL))
		goto err_nonempty;
	return 0;

err_nonempty:
	pthread_mutex_destroy(&r->mu);
err_mu:
	free(r->buf);
	r->buf = NULL;
err_buf:
	return -1;
}

void lab_ring_destroy(struct lab_ring *r)
{
	if (!r->buf)
		return;
	pthread_cond_destroy(&r->nonfull);
	pthread_cond_destroy(&r->nonempty);
	pthread_mutex_destroy(&r->mu);
	free(r->buf);
	r->buf = NULL;
}

void lab_ring_wake_all(struct lab_ring *r)
{
	pthread_mutex_lock(&r->mu);
	pthread_cond_broadcast(&r->nonempty);
	pthread_cond_broadcast(&r->nonfull);
	pthread_mutex_unlock(&r->mu);
}

int lab_ring_try_pop(struct lab_ring *r, struct lab_job *j)
{
	int rv = -1;

	pthread_mutex_lock(&r->mu);
	if (r->count > 0) {
		*j = r->buf[r->head];
		r->head = (r->head + 1) % r->cap;
		r->count--;
		pthread_cond_signal(&r->nonfull);
		rv = 0;
	}
	pthread_mutex_unlock(&r->mu);
	return rv;
}

int lab_ring_push_retry(struct lab_ring *r, const struct lab_job *j,
			volatile sig_atomic_t *stop)
{
	pthread_mutex_lock(&r->mu);
	for (;;) {
		if (*stop) {
			pthread_mutex_unlock(&r->mu);
			return -1;
		}
		if (r->count < r->cap)
			break;
		pthread_cond_wait(&r->nonfull, &r->mu);
	}
	r->buf[r->tail] = *j;
	r->tail = (r->tail + 1) % r->cap;
	r->count++;
	pthread_cond_signal(&r->nonempty);
	pthread_mutex_unlock(&r->mu);
	return 0;
}

void *lab_ptr(struct lab_pair *p, uint64_t addr)
{
	return xsk_umem__get_data(p->bufs, addr);
}

static int lab_sock_shared(struct lab_pair *p, const char *ifn,
			   struct xsk_socket **xsk, struct xsk_ring_cons *rx,
			   struct xsk_ring_prod *tx)
{
	struct xsk_socket_config cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_DRV_MODE,
		.bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
	};

	return xsk_socket__create_shared(xsk, ifn, 0, p->umem, rx, tx,
					 &p->umem_fq, &p->umem_cq, &cfg);
}

static int lab_prime_fq(struct lab_pair *p, uint32_t want)
{
	uint32_t idx;
	int ret;
	uint32_t i;

	for (;;) {
		ret = xsk_ring_prod__reserve(&p->umem_fq, want, &idx);
		if (ret == (int)want)
			break;
		if (ret < 0)
			return -1;
		sched_yield();
	}
	for (i = 0; i < want; i++) {
		uint64_t a;

		if (pool_pop(p, &a))
			return -1;
		*xsk_ring_prod__fill_addr(&p->umem_fq, idx++) = a;
	}
	xsk_ring_prod__submit(&p->umem_fq, want);
	return 0;
}

int lab_pair_open(struct lab_pair *p, const char *loc_if, const char *wan_if,
		  const char *bpf_loc_o, const char *bpf_wan_o)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	struct xsk_umem_config ucfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = LAB_FRAME,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	struct bpf_program *pl = NULL, *pw = NULL;
	int err = 0;

	memset(p, 0, sizeof(*p));
	if (pthread_mutex_init(&p->pool_mu, NULL))
		return -1;
	if (pthread_mutex_init(&p->umem_fq_mu, NULL) ||
	    pthread_mutex_init(&p->umem_cq_tx_mu, NULL)) {
		pthread_mutex_destroy(&p->pool_mu);
		return -1;
	}
	p->frame_size = LAB_FRAME;
	p->n_frames = LAB_RING_CAP;
	p->stack_cap = p->n_frames;
	p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;

	if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
		pthread_mutex_destroy(&p->umem_cq_tx_mu);
		pthread_mutex_destroy(&p->umem_fq_mu);
		pthread_mutex_destroy(&p->pool_mu);
		return -1;
	}

	p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p->bufs == MAP_FAILED) {
		pthread_mutex_destroy(&p->umem_cq_tx_mu);
		pthread_mutex_destroy(&p->umem_fq_mu);
		pthread_mutex_destroy(&p->pool_mu);
		return -1;
	}

	p->frame_stack = calloc(p->stack_cap, sizeof(uint64_t));
	if (!p->frame_stack)
		goto err_mmap;

	for (uint32_t i = 0; i < p->n_frames; i++)
		p->frame_stack[i] = (uint64_t)i * p->frame_size;
	p->stack_nt = p->n_frames;

	err = xsk_umem__create(&p->umem, p->bufs, p->bufsize, &p->umem_fq,
			       &p->umem_cq, &ucfg);
	if (err)
		goto err_stack;

	err = lab_sock_shared(p, loc_if, &p->loc.xsk, &p->loc.rx, &p->loc.tx);
	if (err)
		goto err_umem;
	p->loc.ifindex = if_nametoindex(loc_if);
	if (!p->loc.ifindex) {
		err = -EINVAL;
		goto err_loc_xsk;
	}

	err = lab_sock_shared(p, wan_if, &p->wan.xsk, &p->wan.rx, &p->wan.tx);
	if (err)
		goto err_loc_xsk;
	p->wan.ifindex = if_nametoindex(wan_if);
	if (!p->wan.ifindex) {
		err = -EINVAL;
		goto err_wan_xsk;
	}

	if (lab_prime_fq(p, ucfg.fill_size))
		goto err_wan_xsk;

	p->bpf_loc = bpf_object__open_file(bpf_loc_o, NULL);
	p->bpf_wan = bpf_object__open_file(bpf_wan_o, NULL);
	if (!p->bpf_loc || !p->bpf_wan)
		goto err_wan_xsk;

	if (bpf_object__load(p->bpf_loc) || bpf_object__load(p->bpf_wan))
		goto err_bpf;

	pl = bpf_object__find_program_by_name(p->bpf_loc, "xdp_redirect_prog");
	pw = bpf_object__find_program_by_name(p->bpf_wan, "xdp_wan_redirect_prog");
	if (!pl || !pw)
		goto err_bpf;

	{
		struct bpf_map *ml =
			bpf_object__find_map_by_name(p->bpf_loc, "xsks_map");
		struct bpf_map *mw =
			bpf_object__find_map_by_name(p->bpf_wan, "wan_xsks_map");
		int fd_loc, fd_wan;

		if (!ml || !mw)
			goto err_bpf;
		fd_loc = bpf_map__fd(ml);
		fd_wan = bpf_map__fd(mw);
		if (fd_loc < 0 || fd_wan < 0)
			goto err_bpf;
		if (lab_xskmap_bind(p->loc.xsk, fd_loc) ||
		    lab_xskmap_bind(p->wan.xsk, fd_wan))
			goto err_bpf;
	}

	p->lnk_loc = bpf_program__attach_xdp(pl, p->loc.ifindex);
	p->lnk_wan = bpf_program__attach_xdp(pw, p->wan.ifindex);
	if (!p->lnk_loc || !p->lnk_wan)
		goto err_bpf;

	return 0;

err_bpf:
	if (p->lnk_wan)
		bpf_link__destroy(p->lnk_wan);
	p->lnk_wan = NULL;
	if (p->lnk_loc)
		bpf_link__destroy(p->lnk_loc);
	p->lnk_loc = NULL;
	if (p->bpf_wan)
		bpf_object__close(p->bpf_wan);
	p->bpf_wan = NULL;
	if (p->bpf_loc)
		bpf_object__close(p->bpf_loc);
	p->bpf_loc = NULL;
err_wan_xsk:
	xsk_socket__delete(p->wan.xsk);
	p->wan.xsk = NULL;
err_loc_xsk:
	xsk_socket__delete(p->loc.xsk);
	p->loc.xsk = NULL;
err_umem:
	xsk_umem__delete(p->umem);
	p->umem = NULL;
err_stack:
	free(p->frame_stack);
	p->frame_stack = NULL;
err_mmap:
	if (p->bufs && p->bufs != MAP_FAILED) {
		munmap(p->bufs, p->bufsize);
		p->bufs = NULL;
	}
	pthread_mutex_destroy(&p->umem_cq_tx_mu);
	pthread_mutex_destroy(&p->umem_fq_mu);
	pthread_mutex_destroy(&p->pool_mu);
	return -1;
}

void lab_pair_close(struct lab_pair *p)
{
	if (p->lnk_wan) {
		bpf_link__destroy(p->lnk_wan);
		p->lnk_wan = NULL;
	}
	if (p->lnk_loc) {
		bpf_link__destroy(p->lnk_loc);
		p->lnk_loc = NULL;
	}
	if (p->bpf_wan) {
		bpf_object__close(p->bpf_wan);
		p->bpf_wan = NULL;
	}
	if (p->bpf_loc) {
		bpf_object__close(p->bpf_loc);
		p->bpf_loc = NULL;
	}
	if (p->wan.xsk) {
		xsk_socket__delete(p->wan.xsk);
		p->wan.xsk = NULL;
	}
	if (p->loc.xsk) {
		xsk_socket__delete(p->loc.xsk);
		p->loc.xsk = NULL;
	}
	if (p->umem) {
		xsk_umem__delete(p->umem);
		p->umem = NULL;
	}
	free(p->frame_stack);
	p->frame_stack = NULL;
	if (p->bufs) {
		munmap(p->bufs, p->bufsize);
		p->bufs = NULL;
	}
	pthread_mutex_destroy(&p->umem_cq_tx_mu);
	pthread_mutex_destroy(&p->umem_fq_mu);
	pthread_mutex_destroy(&p->pool_mu);
}

int lab_recv_loc(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max)
{
	uint32_t idx_rx;
	unsigned int rcvd;
	int i, ret;
	uint32_t idx_fq;
	int out = 0;

	pthread_mutex_lock(&p->umem_fq_mu);

	rcvd = xsk_ring_cons__peek(&p->loc.rx, (uint32_t)max, &idx_rx);
	if (!rcvd) {
		if (xsk_ring_prod__needs_wakeup(&p->umem_fq))
			(void)recvfrom(xsk_socket__fd(p->loc.xsk), NULL, 0,
				       MSG_DONTWAIT, NULL, 0);
		pthread_mutex_unlock(&p->umem_fq_mu);
		return 0;
	}

	for (;;) {
		ret = xsk_ring_prod__reserve(&p->umem_fq, rcvd, &idx_fq);
		if (ret == (int)rcvd)
			break;
		if (ret < 0) {
			pthread_mutex_unlock(&p->umem_fq_mu);
			return -1;
		}
		if (xsk_ring_prod__needs_wakeup(&p->umem_fq))
			(void)recvfrom(xsk_socket__fd(p->loc.xsk), NULL, 0,
				       MSG_DONTWAIT, NULL, 0);
	}

	for (i = 0; i < (int)rcvd; i++) {
		const struct xdp_desc *desc =
			xsk_ring_cons__rx_desc(&p->loc.rx, idx_rx++);
		uint64_t addr = desc->addr;
		uint32_t len = desc->len;
		uint64_t rep;

		addrs[i] = addr;
		lens[i] = len;
		pool_pop(p, &rep);
		*xsk_ring_prod__fill_addr(&p->umem_fq, idx_fq++) = rep;
	}
	xsk_ring_prod__submit(&p->umem_fq, rcvd);
	xsk_ring_cons__release(&p->loc.rx, rcvd);
	out = (int)rcvd;
	pthread_mutex_unlock(&p->umem_fq_mu);
	return out;
}

int lab_recv_wan(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max)
{
	uint32_t idx_rx;
	unsigned int rcvd;
	int i, ret;
	uint32_t idx_fq;
	int out = 0;

	pthread_mutex_lock(&p->umem_fq_mu);

	rcvd = xsk_ring_cons__peek(&p->wan.rx, (uint32_t)max, &idx_rx);
	if (!rcvd) {
		if (xsk_ring_prod__needs_wakeup(&p->umem_fq))
			(void)recvfrom(xsk_socket__fd(p->wan.xsk), NULL, 0,
				       MSG_DONTWAIT, NULL, 0);
		pthread_mutex_unlock(&p->umem_fq_mu);
		return 0;
	}

	for (;;) {
		ret = xsk_ring_prod__reserve(&p->umem_fq, rcvd, &idx_fq);
		if (ret == (int)rcvd)
			break;
		if (ret < 0) {
			pthread_mutex_unlock(&p->umem_fq_mu);
			return -1;
		}
		if (xsk_ring_prod__needs_wakeup(&p->umem_fq))
			(void)recvfrom(xsk_socket__fd(p->wan.xsk), NULL, 0,
				       MSG_DONTWAIT, NULL, 0);
	}

	for (i = 0; i < (int)rcvd; i++) {
		const struct xdp_desc *desc =
			xsk_ring_cons__rx_desc(&p->wan.rx, idx_rx++);
		uint64_t addr = desc->addr;
		uint32_t len = desc->len;
		uint64_t rep;

		addrs[i] = addr;
		lens[i] = len;
		pool_pop(p, &rep);
		*xsk_ring_prod__fill_addr(&p->umem_fq, idx_fq++) = rep;
	}
	xsk_ring_prod__submit(&p->umem_fq, rcvd);
	xsk_ring_cons__release(&p->wan.rx, rcvd);
	out = (int)rcvd;
	pthread_mutex_unlock(&p->umem_fq_mu);
	return out;
}

static int lab_tx_one(struct lab_pair *p, struct lab_zc_port *port,
		      uint64_t addr, uint32_t len)
{
	uint32_t idx_tx;
	int ret;

	pthread_mutex_lock(&p->umem_cq_tx_mu);

	lab_complete_cq(p, XSK_RING_CONS__DEFAULT_NUM_DESCS);

	for (;;) {
		ret = xsk_ring_prod__reserve(&port->tx, 1, &idx_tx);
		if (ret == 1)
			break;
		if (ret < 0) {
			pthread_mutex_unlock(&p->umem_cq_tx_mu);
			return -1;
		}
		if (xsk_ring_prod__needs_wakeup(&port->tx))
			(void)sendto(xsk_socket__fd(port->xsk), NULL, 0,
				       MSG_DONTWAIT, NULL, 0);
	}

	xsk_ring_prod__tx_desc(&port->tx, idx_tx)->addr = addr;
	xsk_ring_prod__tx_desc(&port->tx, idx_tx)->len = len;
	xsk_ring_prod__submit(&port->tx, 1);
	(void)sendto(xsk_socket__fd(port->xsk), NULL, 0, MSG_DONTWAIT, NULL,
		     0);

	pthread_mutex_unlock(&p->umem_cq_tx_mu);
	return 0;
}

int lab_tx_loc(struct lab_pair *p, uint64_t addr, uint32_t len)
{
	return lab_tx_one(p, &p->loc, addr, len);
}

int lab_tx_wan(struct lab_pair *p, uint64_t addr, uint32_t len)
{
	return lab_tx_one(p, &p->wan, addr, len);
}