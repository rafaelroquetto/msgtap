#pragma once

#include <cstdint>
#include <string>

struct HTTPRequest
{
	enum class Type : uint8_t
	{
		Client,
		Server,
		Unknown
	};

	uint64_t cookie;

	uint64_t startTimeNS;

	uint32_t pid;

	uint32_t localIP;
	uint32_t localPort;
	uint32_t peerIP;
	uint32_t peerPort;

	std::string path;

	Type type;
};
