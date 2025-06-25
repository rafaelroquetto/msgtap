#include "ebpfmanager.h"

#include <cstdint>
#include <format>
#include <print>
#include <span>
#include <string>
#include <string_view>

enum class socket_type : uint8_t
{
	client,
	server
};

struct traceparent
{
	uint8_t version;
	uint8_t trace_id[16];
	uint8_t span_id[8];
	uint8_t flags;
};

struct http_request_event
{
	uint32_t pid;
	uint32_t local_ip;
	uint32_t local_port;
	uint32_t peer_ip;
	uint32_t peer_port;
	uint32_t payload_len;

	struct traceparent tp;

	socket_type sock_type;

	/* payload */
};

static std::string_view sockTypeToSting(socket_type s)
{
	switch (s)
	{
		case socket_type::client:
			return "CLIENT";
		case socket_type::server:
			return "SERVER";
	}

	return "UNKNOWN";
}

static std::string ipToString(uint32_t addr)
{
	return std::format("{}.{}.{}.{}",
			(addr >> 24) & 0xFF,
			(addr >> 16) & 0xFF,
			(addr >>  8) & 0xFF,
			(addr >>  0) & 0xFF);
}

static std::string_view stringViewFromSpan(std::span<const std::byte> s)
{
	return std::string_view(reinterpret_cast<const char*>(s.data()), s.size());
}

static void handleEvent(std::span<const std::byte> eventData)
{
	const auto *ev = reinterpret_cast<const http_request_event*>(eventData.data());

	std::print("{} {} local: {}:{} | peer: {}:{} ",
			sockTypeToSting(ev->sock_type),
			ev->pid,
			ipToString(ev->local_ip),
			ev->local_port,
			ipToString(ev->peer_ip),
			ev->peer_port);

	const auto method = eventData.subspan(sizeof(*ev));

	std::println("path '{}'", stringViewFromSpan(method));
}

int main(int argc, char *argv[])
{
	EBPFManager mgr;

	mgr.setEventCallback(handleEvent);

	if (!mgr.init())
	{
		std::println(stderr, "init failed");
		return 0;
	}

	mgr.exec();

	return 0;
}
