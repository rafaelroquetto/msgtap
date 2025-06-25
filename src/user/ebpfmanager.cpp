#include "ebpfmanager.h"
#include "uniquefd.h"

#include <print>
#include <type_traits>

#include <fcntl.h>

template <typename ...Args>
static void printError(std::format_string<Args...> fmt, Args&& ...args)
{
	std::println(stderr, fmt, std::forward<Args>(args)...);
}

bool EBPFManager::init()
{
	m_skel = BPFSkelUptr(msgtap_bpf::open_and_load());

	if (!m_skel)
	{
		printError("error loading ebpf file");
		return false;
	}

	if (!attachCgroup(m_skel->progs.sockmap_tracker, "/sys/fs/cgroup"))
		return false;

	const bool attached = attachSockMaps(m_skel->maps.sock_hash,
			m_skel->progs.egress,
			m_skel->progs.ingress_parser,
			m_skel->progs.ingress_verdict);

	if (!attached)
	{
		printError("error attaching socket maps");
		return false;
	}

	const auto handleEventThunk = [](void *ctx, void *data, size_t size) -> int
	{
		const auto sp = std::span(reinterpret_cast<const std::byte*>(data), size);
		return static_cast<EBPFManager*>(ctx)->handleEvent(sp);
	};

	m_ringBuf = BPFRingBufUptr(ring_buffer__new(bpf_map__fd(m_skel->maps.rb),
					handleEventThunk, this, nullptr));

	if (!m_ringBuf)
	{
		printError("error intializing ring buffer");
		return false;
	}

	return true;
}

void EBPFManager::exec()
{
	for (;;)
	{
		ring_buffer__poll(m_ringBuf.get(), 100);
	}
}

void EBPFManager::setEventCallback(EventCB cb)
{
	m_callback = std::move(cb);
}

bool EBPFManager::attachSockMap(const struct bpf_map *map, const struct bpf_program *prog)
{
	BPFLinkUptr link(bpf_program__attach_sockmap(prog, bpf_map__fd(map)));

	if (!link)
		return false;

	m_links.emplace_back(std::move(link));

	return true;
}

bool EBPFManager::attachSockMaps(const struct bpf_map *map, const auto ...args)
{
	return (attachSockMap(map, args) && ...);
}

bool EBPFManager::attachCgroup(const struct bpf_program *prog, const char *cgroup)
{
	m_cgroupFD = UniqueFD(::open(cgroup, O_RDONLY));

	if (!m_cgroupFD)
	{
		printError("error opening cgroup");
		return false;
	}

	BPFLinkUptr link(bpf_program__attach_cgroup(prog, static_cast<int>(m_cgroupFD)));

	if (!link)
	{
		printError("error attaching cgroup");
		return false;
	}

	m_links.emplace_back(std::move(link));

	return true;
}

int EBPFManager::handleEvent(std::span<const std::byte> data)
{
	if (m_callback)
		m_callback(data);

	return 0;
}
