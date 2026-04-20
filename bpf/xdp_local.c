#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	__u8 *ip0;
	__u8 vih, proto;
	__u32 ihl_bytes;

	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	eth = data;
	if (eth->h_proto == bpf_htons(ETH_P_ARP))
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip0 = (__u8 *)data + sizeof(struct ethhdr);
	if (ip0 + 20 > (__u8 *)data_end)
		return XDP_PASS;

	vih = *ip0;
	if ((vih >> 4) != 4)
		return XDP_PASS;
	if ((vih & 0x0f) < 5)
		return XDP_PASS;

	ihl_bytes = (__u32)(vih & 0x0f) * 4u;
	if (ip0 + ihl_bytes > (__u8 *)data_end)
		return XDP_PASS;

	proto = *(ip0 + 9);
	if (proto == 1)
		return XDP_PASS;

	return bpf_redirect_map(&xsks_map, 0, 0);
}

char _license[] SEC("license") = "GPL";
