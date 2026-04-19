// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} wan_xsks_map SEC(".maps");

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;

	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	eth = data;
	if (eth->h_proto == bpf_htons(ETH_P_ARP))
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return XDP_PASS;

	ip = data + sizeof(struct ethhdr);
	if (ip->protocol == 1)
		return XDP_PASS;

	return bpf_redirect_map(&wan_xsks_map, 0, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
