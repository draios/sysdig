//
// k8s_poller.h
//

#pragma once

#include "k8s_common.h"
#include <map>

class k8s_http;

class k8s_poller
{
public:
	typedef std::map<int, k8s_http*> socket_map_t;

	k8s_poller(bool do_loop = true, long timeout_ms = 0L);

	~k8s_poller();

	void add(k8s_http* handler);

	void remove(int sockfd);

	void remove_all();

	int subscription_count() const;

	void poll();

	void stop();

	bool is_active() const;

private:
	socket_map_t m_sockets;
	fd_set       m_infd;
	fd_set       m_errfd;
	int          m_nfds;
	bool         m_loop;
	long         m_timeout_ms;
	bool         m_stopped;
	K8S_DECLARE_MUTEX;
};

inline void k8s_poller::stop()
{
	m_stopped = true;
}