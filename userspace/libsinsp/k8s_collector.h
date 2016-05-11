//
// k8s_collector.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "k8s_common.h"
#include <map>
#include <atomic>

class k8s_http;

class k8s_collector
{
public:
	typedef std::map<int, k8s_http*> socket_map_t;

	k8s_collector(bool do_loop = true, long timeout_ms = 1000L);

	~k8s_collector();

	void add(k8s_http* handler);

	void remove_all();

	int subscription_count() const;

	void get_data();

	void stop();

	bool is_active() const;

private:
	void clear();
	void remove(socket_map_t::iterator& it);

	socket_map_t     m_sockets;
	std::atomic<int> m_subscription_count;
	fd_set           m_infd;
	fd_set           m_errfd;
	int              m_nfds;
	bool             m_loop;
	long             m_timeout_ms;
	bool             m_stopped;
};

inline void k8s_collector::stop()
{
	m_stopped = true;
}

#endif // HAS_CAPTURE