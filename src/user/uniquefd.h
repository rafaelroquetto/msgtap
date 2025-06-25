#pragma once

#include <unistd.h>

class UniqueFD
{
public:
	UniqueFD()
		: m_fd(-1)
	{
	}

	explicit UniqueFD(int fd)
		: m_fd(fd)
	{
	}

	UniqueFD(const UniqueFD &) = delete;

	UniqueFD(UniqueFD &&other)
	{
		m_fd = other.release();
	}

	~UniqueFD()
	{
		reset();
	}

	UniqueFD& operator=(const UniqueFD &) = delete;

	UniqueFD& operator=(UniqueFD &&other)
	{
		if (this == &other)
			return *this;

		m_fd = other.release();

		return *this;
	}

	void reset()
	{
		if (m_fd >= 0)
			::close(m_fd);

		m_fd = -1;
	}

	int release()
	{
		const int ret = m_fd;

		m_fd = -1;

		return ret;
	}

	int handle() const
	{
		return m_fd;
	}

	explicit operator int() const
	{
		return handle();
	}

	explicit operator bool() const
	{
		return  handle() != -1;
	}

private:
	int m_fd;
};
