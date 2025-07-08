#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "http.h"
#include "skb_utils.h"
#include "scratch_mem.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u64);
} sock_hash SEC(".maps");

struct span
{
	const unsigned char *ptr;
	__u32 len;
};

enum sock_type : __u8
{
	sock_type_client,
	sock_type_server
};

enum sock_state : __u8
{
	sock_state_idle,
	sock_state_buffering,
	sock_state_request_header,
	sock_state_request_ongoing,
};

struct traceparent
{
	__u8 version;
	__u8 trace_id[16];
	__u8 span_id[8];
	__u8 flags;
};

struct socket_data
{
	__u64 cookie;
	__u32 pid;
	__u32 local_ip;
	__u32 local_port;
	__u32 peer_ip;
	__u32 peer_port;

	struct traceparent tp;

	enum sock_type type;
	enum sock_state state;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct socket_data);
} sk_storage_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

enum event_type : __u8
{
	http_request_start,
	http_request_finish,
	http_request_timeout,
};

struct http_request_event
{
	enum event_type type;

	__u64 cookie;
	__u64 timestamp;
	__u32 pid;
	__u32 local_ip;
	__u32 local_port;
	__u32 peer_ip;
	__u32 peer_port;
	__u32 payload_len;

	struct traceparent tp;

	enum sock_type sock_type;

	/* payload */
};

struct http_request_finished_event
{
	enum event_type type;
	__u64 cookie;
	__u64 timestamp;
	__u16 status_code;
};

struct http_request_timedout_event
{
	enum event_type type;
	__u64 cookie;
	__u64 timestamp;
};

enum : __u32
{
	INVALID_POS = 0xffffffffu,
	MAX_LOOP_ITER = 0x3ffu,
};

enum
{
	TAIL_CLIENT_HTTP_REQ,
};

int handle_client_http_request(struct sk_msg_md *msg);

struct
{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_map SEC(".maps") = {
	.values = {
		[TAIL_CLIENT_HTTP_REQ] = (void *)&handle_client_http_request,
	},
};


static const unsigned char HEADER_SEP[] = {'\r', '\n', '\r', '\n'};
static const char HTTP_RESP[] = "HTTP/1.X 000 ";


static __always_inline struct span make_span(const unsigned char *ptr, __u32 len)
{
	const struct span s = {ptr, len};
	return s;
}

static __always_inline struct traceparent make_traceparent()
{
	struct traceparent tp;
	tp.version = 0;
	tp.flags = 0;

	__u32 rnd = bpf_get_prandom_u32();
	__builtin_memcpy(&tp.trace_id[0], &rnd, sizeof(rnd));

	rnd = bpf_get_prandom_u32();
	__builtin_memcpy(&tp.trace_id[4], &rnd, sizeof(rnd));

	rnd = bpf_get_prandom_u32();
	__builtin_memcpy(&tp.trace_id[8], &rnd, sizeof(rnd));

	rnd = bpf_get_prandom_u32();
	__builtin_memcpy(&tp.trace_id[12], &rnd, sizeof(rnd));

	rnd = bpf_get_prandom_u32();
	__builtin_memcpy(&tp.span_id[0], &rnd, sizeof(rnd));

	rnd = bpf_get_prandom_u32();
	__builtin_memcpy(&tp.span_id[4], &rnd, sizeof(rnd));

	return tp;
}

static __always_inline const char* state_str(int state)
{
	switch (state)
	{
		case BPF_TCP_ESTABLISHED: return "BPF_TCP_ESTABLISHED";
		case BPF_TCP_SYN_SENT: return "BPF_TCP_SYN_SENT";
		case BPF_TCP_SYN_RECV: return "BPF_TCP_SYN_RECV";
		case BPF_TCP_FIN_WAIT1: return "BPF_TCP_FIN_WAIT1";
		case BPF_TCP_FIN_WAIT2: return "BPF_TCP_FIN_WAIT2";
		case BPF_TCP_TIME_WAIT: return "BPF_TCP_TIME_WAIT";
		case BPF_TCP_CLOSE: return "BPF_TCP_CLOSE";
		case BPF_TCP_CLOSE_WAIT: return "BPF_TCP_CLOSE_WAIT";
		case BPF_TCP_LAST_ACK: return "BPF_TCP_LAST_ACK";
		case BPF_TCP_LISTEN: return "BPF_TCP_LISTEN";
		case BPF_TCP_CLOSING: return "BPF_TCP_CLOSING";
		case BPF_TCP_NEW_SYN_RECV: return "BPF_TCP_NEW_SYN_RECV";
		case BPF_TCP_BOUND_INACTIVE: return "BPF_TCP_BOUND_INACTIVE";
	}

	return "UNKNOWN";
}

static __always_inline struct socket_data *new_sk_storage(const struct bpf_sock *sk)
{
	const __u64 key = (__u64) sk;

	const struct socket_data init = {};

	bpf_map_update_elem(&sk_storage_map, &key, &init, BPF_ANY);

	return bpf_map_lookup_elem(&sk_storage_map, &key);
}

static __always_inline struct socket_data *get_sk_storage(const struct bpf_sock *sk)
{
	const __u64 key = (__u64) sk;

	return bpf_map_lookup_elem(&sk_storage_map, &key);
}

static __always_inline void clear_sk_storage(const struct bpf_sock *sk)
{
	const __u64 key = (__u64) sk;
	bpf_map_delete_elem(&sk_storage_map, &key);
}

static __always_inline void ip4_to_str(__u32 ip, char *buf, __u32 buf_size)
{
	// IP is in host byte order, so split manually
	__u8 *bytes = (__u8 *)&ip;
	__u64 data[] = {bytes[0], bytes[1], bytes[2], bytes[3]};

	// Format into buffer: e.g., "127.0.0.1"
	bpf_snprintf(buf, buf_size, "%d.%d.%d.%d", data, sizeof(data));
}

static __always_inline void dump_sock_data(const struct socket_data *data)
{
	char ip_buf[] = "000.000.000.000";

	bpf_printk("=== BEGIN SOCK DATA ===");
	bpf_printk("pid: %u", data->pid);

	ip4_to_str(bpf_htonl(data->local_ip), (char*) &ip_buf, sizeof(ip_buf));

	bpf_printk("client addr: (%x)%s:%u", data->local_ip, ip_buf, data->local_port);

	ip4_to_str(bpf_htonl(data->peer_ip), (char*) &ip_buf, sizeof(ip_buf));
	bpf_printk("server addr: (%x)%s:%u", data->peer_ip, ip_buf, data->peer_port);
	bpf_printk("=== END SOCK DATA ===\n");
}

static __always_inline void print_req_info(const struct socket_data *data, struct bpf_sock *sk)
{
	char ip_buf[] = "000.000.000.000";
	char ip_buf2[] = "000.000.000.000";

	ip4_to_str(bpf_htonl(data->local_ip), (char*) &ip_buf, sizeof(ip_buf));
	ip4_to_str(bpf_htonl(data->peer_ip), (char*) &ip_buf2, sizeof(ip_buf2));

	const __u64 pid_tgid = bpf_get_current_pid_tgid();

	const char *type_str = data->type == sock_type_client ? "HTTPClient" : "HTTP";

	bpf_printk("%s (%llx) > %s:%u -> %s:%u (sk=%llx)",
			type_str, pid_tgid, ip_buf, data->local_port, ip_buf2, data->peer_port, sk);
}

static __always_inline void print_res_info(const struct socket_data *data, struct bpf_sock *sk)
{
	char ip_buf[] = "000.000.000.000";
	char ip_buf2[] = "000.000.000.000";

	ip4_to_str(bpf_htonl(data->local_ip), (char*) &ip_buf, sizeof(ip_buf));
	ip4_to_str(bpf_htonl(data->peer_ip), (char*) &ip_buf2, sizeof(ip_buf2));

	const __u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_printk("(%llx) < %s:%u -> %s:%u (sk=%llx)", pid_tgid, ip_buf, data->local_port, ip_buf2, data->peer_port, sk);
}

static __always_inline void print_pid_tgid()
{
	const __u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_printk("pid = %u, tid = %u\n", pid_tgid >> 32, pid_tgid & 0xffffffff);
}

static __always_inline void print_conn_info(const char *msg, struct bpf_sock_ops *skops)
{
	if (!skops->is_fullsock)
		return;

	const __u32 remote_port = bpf_ntohl(skops->remote_port);

	char buf0[] = "000.000.000.000";
	char buf1[] = "000.000.000.000";

	ip4_to_str(skops->local_ip4, (char*) &buf0, sizeof(buf0));
	ip4_to_str(skops->remote_ip4, (char*) &buf1, sizeof(buf1));

	bpf_printk("%s local: (%x)%s:%u  remote: (%x)%s:%u", msg,
			skops->local_ip4, buf0, skops->local_port,
			skops->remote_ip4, buf1, remote_port);
	bpf_printk("sk = %llx, full_sock = %u", skops->sk, skops->is_fullsock);
	//print_pid_tgid();
}

static __always_inline void on_active_established(struct bpf_sock_ops *skops)
{
	const __u64 key = (__u64) skops->sk;
	bpf_sock_hash_update(skops, &sock_hash, (void*) &key, BPF_ANY);
	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

	struct socket_data *data = new_sk_storage(skops->sk);

	if (!data)
		return;

	data->cookie = bpf_get_socket_cookie(skops);
	data->pid = bpf_get_current_pid_tgid() >> 32;
	data->local_ip = bpf_ntohl(skops->local_ip4);
	data->local_port = skops->local_port;
	data->peer_ip = bpf_ntohl(skops->remote_ip4);
	data->peer_port = bpf_ntohl(skops->remote_port);
	data->type = sock_type_client;
	data->state = sock_state_idle;
}

static __always_inline void on_passive_established(struct bpf_sock_ops *skops)
{
	const __u64 key = (__u64) skops->sk;
	bpf_sock_hash_update(skops, &sock_hash, (void*) &key, BPF_ANY);
	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

	struct socket_data *data = new_sk_storage(skops->sk);

	if (!data)
		return;

	data->cookie = bpf_get_socket_cookie(skops);
	data->pid = bpf_get_current_pid_tgid() >> 32;
	data->local_ip = bpf_ntohl(skops->local_ip4);
	data->local_port = skops->local_port;
	data->peer_ip = bpf_ntohl(skops->remote_ip4);
	data->peer_port = bpf_ntohl(skops->remote_port);
	data->type = sock_type_server;
	data->state = sock_state_idle;
}

static __always_inline void on_state_changed(struct bpf_sock_ops *skops)
{
	if (skops->args[1] != BPF_TCP_CLOSE)
		return;

	const struct socket_data *data = get_sk_storage(skops->sk);

	if (data && data->state == sock_state_request_ongoing)
	{
		struct http_request_timedout_event *ev =
			(struct http_request_timedout_event*) bpf_ringbuf_reserve(&rb, sizeof (*ev), 0);

		if (ev)
		{
			ev->type = http_request_timeout;
			ev->cookie = data->cookie;
			ev->timestamp = bpf_ktime_get_ns();

			bpf_ringbuf_submit(ev, 0);
		}
	}

	const __u64 key = (__u64) skops->sk;
	bpf_map_delete_elem(&sock_hash, &key);
	clear_sk_storage(skops->sk);
}

SEC("sockops")
int sockmap_tracker(struct bpf_sock_ops *skops)
{
	switch (skops->op)
	{
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			on_active_established(skops);
			break;
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			on_passive_established(skops);
			break;
		case BPF_SOCK_OPS_STATE_CB:
			on_state_changed(skops);
			break;
	}

	return 0;
}

static __always_inline const __u32 find_http_header_end(const unsigned char *b,
		const unsigned char *e)
{
	__u32 pos = 0;

	while (b < e && pos < MAX_LOOP_ITER)
	{
		b = check_pkt_access(b, sizeof(HEADER_SEP), e);

		if (!b)
			return INVALID_POS;

		if (__builtin_memcmp(b, HEADER_SEP, sizeof(HEADER_SEP)) == 0)
			return pos;

		++b;
		++pos;
	}

	return INVALID_POS;
}

static __always_inline const unsigned char *
memchar(const unsigned char *haystack,
		char needle,
		const unsigned char *end,
		__u32 size)
{
	for (__u32 i = 0; i < size; ++i) {
		if (&haystack[i] >= end) {
			break;
		}

		if (haystack[i] == needle) {
			return &haystack[i];
		}
	}

	return 0;
}

static __always_inline const unsigned char *
find_first_of(const unsigned char *start, const unsigned char *end, char ch)
{
	return memchar(start, ch, end, 0x3fu);
}


static __always_inline struct span request_url(
		const unsigned char *header_start,
		const unsigned char *header_end)
{
	const unsigned char *b = find_first_of(header_start, header_end, ' ');

	if (!b)
		return make_span(NULL, 0);

	++b;

	const unsigned char *e = find_first_of(b, header_end, ' ');

	if (!e)
		return make_span(NULL, 0);

	const __u32 len = e - b;

	return make_span(b, len);
}

static __always_inline void handle_client_request(struct sk_msg_md *msg,
		struct socket_data *data)
{
	if (data->state != sock_state_idle)
		return;

	if (msg->size < MIN_HTTP_REQ_SIZE)
	{
		bpf_msg_cork_bytes(msg, MIN_HTTP_REQ_SIZE);
		return;
	}

	bpf_msg_pull_data(msg, 0, MIN_HTTP_REQ_SIZE, 0);

	if (!is_http_request(msg_data(msg), msg_data_end(msg)))
	{
		clear_sk_storage(msg->sk);
		return;
	}

	bpf_msg_pull_data(msg, 0, msg->size, 0);

	const __u32 header_end_pos = find_http_header_end(msg_data(msg), msg_data_end(msg));

	if (header_end_pos == INVALID_POS)
	{
		bpf_printk("incomplete http header");
		return;
	}

	bpf_tail_call_static(msg, &prog_array_map, TAIL_CLIENT_HTTP_REQ);
}

static __always_inline __u8 handle_server_request(struct __sk_buff *skb, struct socket_data *data)
{
	bpf_skb_pull_data(skb, 1);

	const unsigned char *start = (const unsigned char*) skb_data(skb);
	const unsigned char *end = (const unsigned char*) skb_data_end(skb);

	start = check_pkt_access(start, 1, end);

	if (!start)
	{
		data->state = sock_state_idle;
		return skb->len;
	}

	// check if maybe this is a HTTP request
	if (data->state == sock_state_idle)
	{
		if (!maybe_http_method_start(*start))
		{
			// not a HTTP socket, no longer track it
			clear_sk_storage(skb->sk);
			return skb->len;
		}

		// potentially a HTTP socket, start buffering
		data->state = sock_state_buffering;
	}

	// if neither buffering nor idle, that means we've already seen the
	// headers and this is just the HTTP body/payload - pass it up
	if (data->state != sock_state_buffering)
		return skb->len;

	if (skb->len < MIN_HTTP_REQ_SIZE)
		return 0; // wait for more data;

	bpf_skb_pull_data(skb, MIN_HTTP_REQ_SIZE);

	// here we have enough data to pass the HTTP method
	if (!is_http_request(skb_data(skb), skb_data_end(skb)))
	{
		// not a HTTP request, stop tracking this socket
		clear_sk_storage(skb->sk);
		return skb->len;
	}

	// at this point, we have a HTTP request - buffer until we have the
	// complete headers
	bpf_skb_pull_data(skb, skb->len);

	const __u32 header_end_pos = find_http_header_end(skb_data(skb), skb_data_end(skb));

	if (header_end_pos == INVALID_POS)
	{
		bpf_printk("incomplete http header");
		return 0;
	}

	// we have a header, pass it up
	data->state = sock_state_request_header;

	return header_end_pos + 4; //TODO 4 is the sizeof \r\n\r\n
}

static __always_inline __u16 parse_http_response_status(const unsigned char *start,
		const unsigned char *end)
{
	if (start + sizeof(HTTP_RESP) > end)
		return 0;

	if (start[0] != HTTP_RESP[0]
			|| start[1] != HTTP_RESP[1]
			|| start[2] != HTTP_RESP[2]
			|| start[3] != HTTP_RESP[3]
			|| start[4] != HTTP_RESP[4]
			|| start[5] != HTTP_RESP[5]
			|| start[6] != HTTP_RESP[6]
			|| start[8] != HTTP_RESP[8])
	{
		return 0;
	}

	__u16 ret = 0;

	for (__u8 i = 9; i <= 11; ++i)
	{
		const char ch = start[i];

		if (ch < '0' || ch > '9')
			return 0;

		ret = ret * 10 + (ch - '0');
	}

	return ret;
}

static __always_inline void handle_server_http_reponse(struct sk_msg_md *msg, struct socket_data *data)
{
	if (data->state != sock_state_request_ongoing)
		return;

	data->state = sock_state_idle;

	bpf_msg_pull_data(msg, 0, sizeof(HTTP_RESP), 0);

	const __u16 status_code = parse_http_response_status(msg_data(msg), msg_data_end(msg));

	struct http_request_finished_event *ev =
		(struct http_request_finished_event*) bpf_ringbuf_reserve(&rb, sizeof (*ev), 0);

	if (!ev)
		return;

	ev->type = http_request_finish;
	ev->cookie = data->cookie;
	ev->timestamp = bpf_ktime_get_ns();
	ev->status_code = status_code;

	bpf_ringbuf_submit(ev, 0);
}

static __always_inline void handle_client_http_response(struct __sk_buff *skb, struct socket_data *data)
{
	if (data->state != sock_state_request_ongoing)
		return;

	data->state = sock_state_idle;

	bpf_skb_pull_data(skb, sizeof(HTTP_RESP));

	const __u16 status_code = parse_http_response_status(skb_data(skb), skb_data_end(skb));

	struct http_request_finished_event *ev =
		(struct http_request_finished_event*) bpf_ringbuf_reserve(&rb, sizeof (*ev), 0);

	if (!ev)
		return;

	ev->type = http_request_finish;
	ev->cookie = data->cookie;
	ev->timestamp = bpf_ktime_get_ns();
	ev->status_code = status_code;

	bpf_ringbuf_submit(ev, 0);
}

SEC("sk_msg")
int egress(struct sk_msg_md *msg)
{
	struct socket_data *data = get_sk_storage(msg->sk);

	if (!data)
		return SK_PASS;

	switch (data->type)
	{
		case sock_type_client:
			handle_client_request(msg, data);
			break;
		case sock_type_server:
			handle_server_http_reponse(msg, data);
			break;
	}

	return SK_PASS;
}

// TAIL_CLIENT_HTTP_REQ
SEC("sk_msg")
int handle_client_http_request(struct sk_msg_md *msg)
{
	struct socket_data *data = get_sk_storage(msg->sk);

	if (!data)
		return SK_PASS;

	const unsigned char *start = msg_data(msg);
	const unsigned char *end = msg_data_end(msg);

	start = check_pkt_access(start, 0x3fu, end);

	if (!start)
	{
		// something is wrong, drop this request
		data->state = sock_state_idle;
		return SK_PASS;
	}

	const struct span url = request_url(start, end);

	if (!url.ptr)
	{
		data->state = sock_state_idle;
		return SK_PASS;
	}

	data->tp = make_traceparent();

	const __u32 event_len = sizeof(struct http_request_event) + url.len;

	struct bpf_dynptr dp;

	if (bpf_ringbuf_reserve_dynptr(&rb, event_len, 0, &dp) != 0)
	{
		bpf_ringbuf_discard_dynptr(&dp, 0);
		bpf_printk("failed to allocate event on the ringbuffer");

		data->state = sock_state_idle;
		return SK_PASS;
	}

	struct http_request_event *ev = (struct http_request_event*) bpf_dynptr_data(&dp, 0, event_len);

	if (!ev)
	{
		bpf_ringbuf_discard_dynptr(&dp, 0);
		data->state = sock_state_idle;
		return SK_PASS;
	}

	ev->cookie = data->cookie;
	ev->timestamp = bpf_ktime_get_ns();
	ev->pid = data->pid;
	ev->local_ip = data->local_ip;
	ev->local_port = data->local_port;
	ev->peer_ip = data->peer_ip;
	ev->peer_port = data->peer_port;
	ev->payload_len = url.len;
	ev->tp = make_traceparent(); // TODO trace context propagation
	ev->sock_type = data->type;

	unsigned char *payload = (unsigned char*) ev + sizeof(*ev);

	if (url.len > 0)
	{
		if (bpf_probe_read_kernel(payload, url.len, url.ptr) != 0)
		{
			bpf_printk("failed to write payload");

			bpf_ringbuf_discard_dynptr(&dp, 0);
			data->state = sock_state_idle;
			return SK_PASS;
		}
	}

	data->state = sock_state_request_ongoing;

	bpf_ringbuf_submit_dynptr(&dp, 0);

	return SK_PASS;
}


SEC("sk_skb/stream_parser")
int ingress_parser(struct __sk_buff *skb)
{
	struct socket_data *data = get_sk_storage(skb->sk);

	if (!data)
		return skb->len;

	if (data->type == sock_type_server)
		return handle_server_request(skb, data);

	if (data->type == sock_type_client)
		handle_client_http_response(skb, data);

	return skb->len;
}

static __always_inline void handle_server_http_request(struct __sk_buff *skb, struct socket_data *data)
{
	const unsigned char *start = skb_data(skb);
	const unsigned char *end = skb_data_end(skb);

	start = check_pkt_access(start, 0x3fu, end);

	if (!start)
	{
		// something is wrong, drop this request
		data->state = sock_state_idle;
		return;
	}

	const struct span url = request_url(start, end);

	if (!url.ptr)
	{
		data->state = sock_state_idle;
		return;
	}

	data->tp = make_traceparent();

	const __u32 event_len = sizeof(struct http_request_event) + url.len;

	struct bpf_dynptr dp;

	if (bpf_ringbuf_reserve_dynptr(&rb, event_len, 0, &dp) != 0)
	{
		bpf_ringbuf_discard_dynptr(&dp, 0);
		bpf_printk("failed to allocate event on the ringbuffer");

		data->state = sock_state_idle;
		return;
	}

	struct http_request_event *ev = (struct http_request_event*) bpf_dynptr_data(&dp, 0, event_len);

	if (!ev)
	{
		bpf_ringbuf_discard_dynptr(&dp, 0);
		data->state = sock_state_idle;
		return;
	}

	ev->cookie = data->cookie;
	ev->timestamp = bpf_ktime_get_ns();
	ev->pid = data->pid;
	ev->local_ip = data->local_ip;
	ev->local_port = data->local_port;
	ev->peer_ip = data->peer_ip;
	ev->peer_port = data->peer_port;
	ev->payload_len = url.len;
	ev->tp = make_traceparent(); // TODO trace context propagation
	ev->sock_type = data->type;

	unsigned char *payload = (unsigned char*) ev + sizeof(*ev);

	const __u32 url_offset = url.ptr - start;

	if (url.len > 0)
	{
		if (bpf_skb_load_bytes(skb, url_offset, payload, url.len) != 0)
		{
			bpf_printk("failed to write payload");

			bpf_ringbuf_discard_dynptr(&dp, 0);
			data->state = sock_state_idle;
			return;
		}
	}

	data->state = sock_state_request_ongoing;

	bpf_ringbuf_submit_dynptr(&dp, 0);
}

SEC("sk_skb/stream_verdict")
int ingress_verdict(struct __sk_buff *skb)
{
	struct socket_data *data = get_sk_storage(skb->sk);

	if (!data)
		return SK_PASS;

	// if not a request header, just pass the payload up
	if (data->state != sock_state_request_header)
		return SK_PASS;

	handle_server_http_request(skb, data);

	return SK_PASS;
}
