#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
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

	if (!xsk || map_fd < 0)
		return -1;
	xfd = xsk_socket__fd(xsk);
	if (xfd < 0)
		return -1;
	if (xsk_socket__update_xskmap(xsk, map_fd) == 0)
		return 0;
	return bpf_map_update_elem(map_fd, &key, &xfd, BPF_ANY);
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

static int lab_sock_open(struct lab_pair *p, struct lab_zc_port *port,
			 const char *ifn)
{
	struct xsk_socket_config cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_SKB_MODE,
		.bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY,
	};

	return xsk_socket__create_shared(&port->xsk, ifn, 0, p->umem,
					 &port->rx, &port->tx,
					 &port->fq, &port->cq, &cfg);
}

static int lab_fq_fill(struct lab_zc_port *port, uint64_t base_addr,
		       uint32_t want, uint32_t frame_size)
{
	uint32_t idx;
	uint32_t i;

	if (xsk_ring_prod__reserve(&port->fq, want, &idx) != want)
		return -1;
	for (i = 0; i < want; i++)
		*xsk_ring_prod__fill_addr(&port->fq, idx++) =
			base_addr + (uint64_t)i * frame_size;
	xsk_ring_prod__submit(&port->fq, want);
	return 0;
}

int lab_pair_open(struct lab_pair *p, const char *loc_if, const char *wan_if,
		  const char *bpf_loc_o, const char *bpf_wan_o)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	struct xsk_umem_config ucfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = LAB_FRAME,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	struct bpf_program *pl = NULL, *pw = NULL;
	struct bpf_map *ml, *mw;
	int err;

	memset(p, 0, sizeof(*p));
	p->frame_size = LAB_FRAME;
	p->n_frames = LAB_RING_CAP;
	p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;

	(void)setrlimit(RLIMIT_MEMLOCK, &rl);

	p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p->bufs == MAP_FAILED) {
		p->bufs = NULL;
		return -1;
	}

	err = xsk_umem__create(&p->umem, p->bufs, p->bufsize, &p->loc.fq,
			       &p->loc.cq, &ucfg);
	if (err)
		goto err_mmap;

	if (lab_sock_open(p, &p->loc, loc_if))
		goto err_umem;
	p->loc.ifindex = if_nametoindex(loc_if);
	if (!p->loc.ifindex)
		goto err_loc_xsk;

	if (lab_sock_open(p, &p->wan, wan_if))
		goto err_loc_xsk;
	p->wan.ifindex = if_nametoindex(wan_if);
	if (!p->wan.ifindex)
		goto err_wan_xsk;

	if (lab_fq_fill(&p->loc, 0, ucfg.fill_size, p->frame_size))
		goto err_wan_xsk;
	if (lab_fq_fill(&p->wan,
			(uint64_t)ucfg.fill_size * p->frame_size,
			ucfg.fill_size, p->frame_size))
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

	if (bpf_xdp_attach(p->loc.ifindex, bpf_program__fd(pl),
			   XDP_FLAGS_SKB_MODE, NULL))
		goto err_bpf;
	p->xdp_loc_on = 1;

	if (bpf_xdp_attach(p->wan.ifindex, bpf_program__fd(pw),
			   XDP_FLAGS_SKB_MODE, NULL))
		goto err_bpf;
	p->xdp_wan_on = 1;

	ml = bpf_object__find_map_by_name(p->bpf_loc, "xsks_map");
	mw = bpf_object__find_map_by_name(p->bpf_wan, "wan_xsks_map");
	if (!ml || !mw)
		goto err_xdp;
	if (lab_xskmap_bind(p->loc.xsk, bpf_map__fd(ml)) ||
	    lab_xskmap_bind(p->wan.xsk, bpf_map__fd(mw)))
		goto err_xdp;

	return 0;

err_xdp:
	if (p->xdp_wan_on) {
		bpf_xdp_detach(p->wan.ifindex, XDP_FLAGS_SKB_MODE, NULL);
		p->xdp_wan_on = 0;
	}
	if (p->xdp_loc_on) {
		bpf_xdp_detach(p->loc.ifindex, XDP_FLAGS_SKB_MODE, NULL);
		p->xdp_loc_on = 0;
	}
err_bpf:
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
err_mmap:
	munmap(p->bufs, p->bufsize);
	p->bufs = NULL;
	return -1;
}

void lab_pair_close(struct lab_pair *p)
{
	if (p->xdp_wan_on) {
		bpf_xdp_detach(p->wan.ifindex, XDP_FLAGS_SKB_MODE, NULL);
		p->xdp_wan_on = 0;
	}
	if (p->xdp_loc_on) {
		bpf_xdp_detach(p->loc.ifindex, XDP_FLAGS_SKB_MODE, NULL);
		p->xdp_loc_on = 0;
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
	if (p->bufs) {
		munmap(p->bufs, p->bufsize);
		p->bufs = NULL;
	}
}

static int lab_recv_port(struct lab_zc_port *port, uint32_t *lens,
			 uint64_t *addrs, int max)
{
	uint32_t idx;
	unsigned int n;
	unsigned int i;

	n = xsk_ring_cons__peek(&port->rx, (uint32_t)max, &idx);
	if (!n) {
		(void)recvfrom(xsk_socket__fd(port->xsk), NULL, 0,
			       MSG_DONTWAIT, NULL, 0);
		return 0;
	}
	for (i = 0; i < n; i++) {
		const struct xdp_desc *d =
			xsk_ring_cons__rx_desc(&port->rx, idx + i);

		addrs[i] = d->addr;
		lens[i] = d->len;
	}
	xsk_ring_cons__release(&port->rx, n);
	return (int)n;
}

int lab_recv_loc(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max)
{
	return lab_recv_port(&p->loc, lens, addrs, max);
}

int lab_recv_wan(struct lab_pair *p, uint32_t *lens, uint64_t *addrs, int max)
{
	return lab_recv_port(&p->wan, lens, addrs, max);
}

static int lab_tx_one(struct lab_zc_port *port, uint64_t addr, uint32_t len)
{
	uint32_t idx;

	if (xsk_ring_prod__reserve(&port->tx, 1, &idx) != 1)
		return -1;
	xsk_ring_prod__tx_desc(&port->tx, idx)->addr = addr;
	xsk_ring_prod__tx_desc(&port->tx, idx)->len = len;
	xsk_ring_prod__submit(&port->tx, 1);
	(void)sendto(xsk_socket__fd(port->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	return 0;
}

int lab_tx_loc(struct lab_pair *p, uint64_t addr, uint32_t len)
{
	return lab_tx_one(&p->loc, addr, len);
}

int lab_tx_wan(struct lab_pair *p, uint64_t addr, uint32_t len)
{
	return lab_tx_one(&p->wan, addr, len);
}
