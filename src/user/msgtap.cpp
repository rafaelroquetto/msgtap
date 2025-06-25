#include "ebpfmanager.h"
#include "httprequest.h"

#include <chrono>
#include <cstdint>
#include <format>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

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

enum class event_type : uint8_t
{
	http_request_start,
	http_request_finish,
	http_request_timeout
};

struct http_request_event
{
	event_type type;
	uint64_t cookie;
	uint64_t timestamp;
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

struct http_request_finished_event
{
	event_type type;
	uint64_t cookie;
	uint64_t timestamp;
	uint16_t status_code;
};

struct http_request_timedout_event
{
	enum event_type type;
	__u64 cookie;
	__u64 timestamp;
};

using RequestMap = std::unordered_map<uint64_t, HTTPRequest>;

static RequestMap &requestMap()
{
	static RequestMap r;
	return r;
}

static std::string_view sockTypeToString(socket_type s)
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

static HTTPRequest::Type sockTypeToRequestType(socket_type s)
{
	switch (s)
	{
		case socket_type::client:
			return HTTPRequest::Type::Client;
		case socket_type::server:
			return HTTPRequest::Type::Server;
	}

	return HTTPRequest::Type::Unknown;
}

static std::string_view reqTypeToString(HTTPRequest::Type t)
{
	switch (t)
	{
		case HTTPRequest::Type::Client:
			return "CLIENT";
		case HTTPRequest::Type::Server:
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

static HTTPRequest makeRequest(const http_request_event &ev, std::string_view method)
{
	return HTTPRequest {
		.cookie = ev.cookie,
		.startTimeNS = ev.timestamp,
		.pid = ev.pid,
		.localIP = ev.local_ip,
		.localPort = ev.local_port,
		.peerIP = ev.peer_ip,
		.peerPort = ev.peer_port,
		.path = std::string(method),
		.type = sockTypeToRequestType(ev.sock_type)
	};
}

static void handleEvent(const http_request_event &ev, std::span<const std::byte> rawData)
{
	const auto method = stringViewFromSpan(rawData.subspan(sizeof(ev)));

	requestMap().emplace(ev.cookie, makeRequest(ev, method));
}

static void handleEvent(const http_request_finished_event &ev, std::span<const std::byte>)
{
	RequestMap &m = requestMap();

	auto it = m.find(ev.cookie);

	if (it == m.end())
	{
		std::println(stderr, "found orphan request {}", ev.cookie);
		return;
	}

	const auto &[_, req] = *it;

	const uint64_t durationNS = ev.timestamp - req.startTimeNS;

	std::println("({}) HTTP {} {} {} local: {}:{} | peer: {}:{} status {} duration {}ns",
			req.cookie,
			reqTypeToString(req.type),
			req.path,
			req.pid,
			ipToString(req.localIP),
			req.localPort,
			ipToString(req.peerIP),
			req.peerPort,
			ev.status_code,
			durationNS);

	m.erase(it);
}

static void handleEvent(const http_request_timedout_event &ev, std::span<const std::byte>)
{
	RequestMap &m = requestMap();

	auto it = m.find(ev.cookie);

	if (it == m.end())
	{
		std::println(stderr, "found orphan request {}", ev.cookie);
		return;
	}

	const auto &[_, req] = *it;

	const uint64_t durationNS = ev.timestamp - req.startTimeNS;

	std::println("({}) HTTP {} {} {} local: {}:{} | peer: {}:{} {}ns TIMEOUT",
			req.cookie,
			reqTypeToString(req.type),
			req.path,
			req.pid,
			ipToString(req.localIP),
			req.localPort,
			ipToString(req.peerIP),
			req.peerPort,
			durationNS);

	m.erase(it);
}

template <typename Event>
static void dispatch(std::span<const std::byte> eventData)
{
	if (eventData.size() < sizeof(Event))
		return;

	handleEvent(*reinterpret_cast<const Event*>(eventData.data()), eventData);
}

static void dispatchEvent(std::span<const std::byte> eventData)
{
	if (eventData.empty())
		return;

	const auto eventType = static_cast<event_type>(eventData.front());

	switch (eventType)
	{
		case event_type::http_request_start:
			dispatch<http_request_event>(eventData);
			break;
		case event_type::http_request_finish:
			dispatch<http_request_finished_event>(eventData);
			break;
		case event_type::http_request_timeout:
			dispatch<http_request_timedout_event>(eventData);
			break;
	}
}

int main(int argc, char *argv[])
{
	EBPFManager mgr;

	mgr.setEventCallback(dispatchEvent);

	if (!mgr.init())
	{
		std::println(stderr, "init failed");
		return 0;
	}

	mgr.exec();

	return 0;
}
