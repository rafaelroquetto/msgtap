#pragma once

#ifdef __BPF__
#	include <bpf/vmlinux.h>

typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;

typedef __s8 int8_t;
typedef __s16 int16_t;
typedef __s32 int32_t;
typedef __s64 int64_t;

#else

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif


#endif

#ifdef __cplusplus
extern "C" {
#endif

struct traceparent
{
	uint8_t version;
	uint8_t trace_id[16];
	uint8_t span_id[8];
	uint8_t flags;
};

enum event_type : uint8_t
{
	http_request_start,
	http_request_finish,
	http_request_timeout,
};

enum socket_type : uint8_t
{
	socket_type_client,
	socket_type_server
};

struct http_request_event
{
	enum event_type type;

	uint64_t cookie;
	uint64_t timestamp;
	uint32_t pid;
	uint32_t local_ip;
	uint32_t local_port;
	uint32_t peer_ip;
	uint32_t peer_port;
	uint32_t payload_len;

	struct traceparent tp;

	enum socket_type sock_type;

	/* payload */
};

struct http_request_finished_event
{
	enum event_type type;
	uint64_t cookie;
	uint64_t timestamp;
	uint16_t status_code;
};

struct http_request_timedout_event
{
	enum event_type type;
	uint64_t cookie;
	uint64_t timestamp;
};

#ifdef __cplusplus
} // extern "C"
#endif
