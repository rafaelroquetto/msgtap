#pragma once

#include "vmlinux.h"

// this "beauty" ensures we hold pkt in the same register being range
// validated
static __always_inline
const unsigned char * check_pkt_access(const unsigned char *buf,
		__u32 offset,
		const unsigned char *end)
{
	const unsigned char *ret;

	asm goto("r4 = %[buf]\n"
			"r4 += %[offset]\n"
			"if r4 > %[end] goto %l[error]\n"
			"%[ret] = %[buf]"
			: [ret] "=r"(ret)
			: [buf] "r"(buf), [end] "r"(end), [offset] "i"(offset)
			: "r4"
			: error);

	return ret;

error:
	return NULL;
}

static __always_inline void *skb_data(struct __sk_buff *ctx)
{
	void *data;

	asm("%[res] = *(u32 *)(%[base] + %[offset])"
			: [res] "=r"(data)
			: [base] "r"(ctx), [offset] "i"(offsetof(struct __sk_buff, data)), "m"(*ctx));

	return data;
}

static __always_inline void *skb_data_end(struct __sk_buff *ctx)
{
	void *data_end;

	asm("%[res] = *(u32 *)(%[base] + %[offset])"
			: [res] "=r"(data_end)
			: [base] "r"(ctx), [offset] "i"(offsetof(struct __sk_buff, data_end)), "m"(*ctx));

	return data_end;
}

static __always_inline void *msg_data(struct sk_msg_md *ctx)
{
	void *data;

	asm("%[res] = *(u64 *)(%[base] + %[offset])"
			: [res] "=r"(data)
			: [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, data)), "m"(*ctx));

	return data;
}

static __always_inline void *msg_data_end(struct sk_msg_md *ctx)
{
	void *data_end;

	asm("%[res] = *(u64 *)(%[base] + %[offset])"
			: [res] "=r"(data_end)
			: [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, data_end)), "m"(*ctx));

	return data_end;
}
