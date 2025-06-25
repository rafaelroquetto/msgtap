#pragma once

#include <linux/bpf.h>

// we need at least 9 bytes (the length of "OPTIONS") to infer whether this is
// a HTTP request
enum : __u8 { MIN_HTTP_REQ_SIZE = 9u };

static __always_inline __u8 is_get(const char *p)
{
	return p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ' && p[4] == '/';
}

static __always_inline __u8 is_post(const char *p)
{
	return p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T' && p[4] == ' ' && p[5] == '/';
}

static __always_inline __u8 is_put(const char *p)
{
	return p[0] == 'P' && p[1] == 'U' && p[2] == 'T' && p[3] == ' ' && p[4] == '/';
}

static __always_inline __u8 is_patch(const char *p)
{
	return p[0] == 'P' && p[1] == 'A' && p[2] == 'T'
		&& p[3] == 'C' && p[4] == 'H' && p[5] == ' ' && p[6] == '/';
}

static __always_inline __u8 is_delete(const char *p)
{
	return p[0] == 'D' && p[1] == 'E' && p[2] == 'L'
		&& p[3] == 'E' && p[4] == 'T' && p[5] == 'E' && p[6] == ' ' && p[7] == '/';
}

static __always_inline __u8 is_head(const char *p)
{
	return p[0] == 'H' && p[1] == 'E' && p[2] == 'A' && p[3] == 'D' && p[4] == ' ' && p[5] == '/';
}

static __always_inline __u8 is_options(const char *p)
{
	return p[0] == 'O' && p[1] == 'P' && p[2] == 'T'
		&& p[3] == 'I' && p[4] == 'O' && p[5] == 'N' && p[6] == 'S' && p[7] == ' ' && p[8] == '/';
}

static __always_inline __u8 maybe_http_method_start(char ch)
{
	switch (ch)
	{
		case 'G':
		case 'P':
		case 'D':
		case 'H':
		case 'O':
			return 1;
	}

	return 0;
}

static __always_inline __u8 is_http_request(const char *data, const char *data_end)
{
	if (data + 1 > data_end)
		return 0;

	if (!maybe_http_method_start(data[0]))
		return 0;

	const char *p = data;

	if (p + MIN_HTTP_REQ_SIZE > data_end)
		return 0;

	//HTTP/1.x
	return is_get(p) || is_post(p) || is_put(p) || is_patch(p)
		|| is_delete(p) || is_head(p) || is_options(p);
}
