#pragma once

#include "msgtap.skel.h"
#include "uniquefd.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <span>
#include <vector>

#include <bpf/libbpf.h>

class EBPFManager
{
public:
	EBPFManager() = default;

	bool init();

	void exec();

	using EventCB = std::move_only_function<void(std::span<const std::byte>)>;

	void setEventCallback(EventCB cb);

private:
	bool attachSockMap(const struct bpf_map *map, const struct bpf_program *prog);
	bool attachSockMaps(const struct bpf_map *map, const auto ...args);
	bool attachCgroup(const struct bpf_program *prog, const char *cgroup);

	int handleEvent(std::span<const std::byte> data);

	template <typename T, void (*freeFunc)(T*)>
	struct GenericDeleter
	{
		void operator()(T *t)
		{
			if (!t)
				return;

			freeFunc(t);
		};
	};

	static void bpfLinkFree(struct bpf_link *link)
	{
		bpf_link__detach(link);
		bpf_link__destroy(link);
	}

	static void bpfSkelDestroy(struct msgtap_bpf *obj)
	{
		msgtap_bpf__destroy(obj);
	}

	using BPFLinkDeleter = GenericDeleter<struct bpf_link, bpfLinkFree>;
	using BPFLinkUptr = std::unique_ptr<struct bpf_link, BPFLinkDeleter>;

	using BPFSkelDeleter = GenericDeleter<struct msgtap_bpf, bpfSkelDestroy>;
	using BPFSkelUptr = std::unique_ptr<struct msgtap_bpf, BPFSkelDeleter>;

	using BPFRingBufDeleter = GenericDeleter<struct ring_buffer, ring_buffer__free>;
	using BPFRingBufUptr = std::unique_ptr<struct ring_buffer, BPFRingBufDeleter>;

	BPFSkelUptr m_skel;

	UniqueFD m_cgroupFD;

	BPFRingBufUptr m_ringBuf;

	std::vector<BPFLinkUptr> m_links;

	EventCB m_callback;
};
