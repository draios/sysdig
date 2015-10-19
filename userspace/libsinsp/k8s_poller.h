//
// k8s_poller.h
//

#pragma once

#include <map>
#include <mutex>

class k8s_http;

class k8s_poller
{
public:
	typedef std::map<int, k8s_http*> socket_map_t;

	k8s_poller(long timeout_ms = 5000L);

	~k8s_poller();

	void add(k8s_http* handler);

	void remove(int sockfd);

	void remove_all();

	void poll();

	void stop();

private:
	socket_map_t m_sockets;
	fd_set       m_infd;
	fd_set       m_errfd;
	int          m_nfds;
	std::mutex   m_mutex;
	long         m_timeout_ms;
	bool         m_stopped;
};

inline void k8s_poller::stop()
{
	m_stopped = true;
}