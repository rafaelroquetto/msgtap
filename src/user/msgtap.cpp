#include "ebpfmanager.h"
#include "httprequest.h"

#include <protocol/protocol.h>

#include <chrono>
#include <cstdint>
#include <format>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

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
		case socket_type_client:
			return "CLIENT";
		case socket_type_server:
			return "SERVER";
	}

	return "UNKNOWN";
}

static HTTPRequest::Type sockTypeToRequestType(socket_type s)
{
	switch (s)
	{
		case socket_type_client:
			return HTTPRequest::Type::Client;
		case socket_type_server:
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

static HTTPRequest makeRequest(const http_request_event &ev, std::string_view url)
{
	return HTTPRequest {
		.cookie = ev.cookie,
		.startTimeNS = ev.timestamp,
		.pid = ev.pid,
		.localIP = ev.local_ip,
		.localPort = ev.local_port,
		.peerIP = ev.peer_ip,
		.peerPort = ev.peer_port,
		.path = std::string(url),
		.type = sockTypeToRequestType(ev.sock_type)
	};
}

static void handleEvent(const http_request_event &ev, std::span<const std::byte> rawData)
{
	const auto url = stringViewFromSpan(rawData.subspan(sizeof(ev)));

	requestMap().emplace(ev.cookie, makeRequest(ev, url));
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
