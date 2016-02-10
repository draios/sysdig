//
// mesos_collector.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "mesos_common.h"
#include <map>
#include <memory>

class mesos_http;

class mesos_collector
{
public:
	typedef std::map<int, std::shared_ptr<mesos_http>> socket_map_t;

	mesos_collector(bool do_loop = true, long timeout_ms = 1000L);

	~mesos_collector();

	void add(std::shared_ptr<mesos_http> handler);

	void remove_all();

	int subscription_count() const;

	void get_data();

	void stop();

	bool is_active() const;
	bool is_healthy(int expected_count) const;

	bool has(std::shared_ptr<mesos_http> handler);
	bool remove(std::shared_ptr<mesos_http> handler);

private:
	void clear();
	socket_map_t::iterator& remove(socket_map_t::iterator& it);

	socket_map_t     m_sockets;
	fd_set           m_infd;
	fd_set           m_errfd;
	int              m_nfds;
	bool             m_loop;
	long             m_timeout_ms;
	bool             m_stopped;
};

inline void mesos_collector::stop()
{
	m_stopped = true;
}

#endif // HAS_CAPTURE