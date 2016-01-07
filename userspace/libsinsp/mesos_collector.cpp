//
// mesos_collector.cpp
//

#ifdef HAS_CAPTURE

#include "sinsp.h"
#include "sinsp_int.h"
#include "mesos_collector.h"
#include "mesos_http.h"
#include <string.h>
#include <sstream>
#include <unistd.h>


mesos_collector::mesos_collector(bool do_loop, long timeout_ms): m_subscription_count(0),
	m_nfds(0),
	m_loop(do_loop),
	m_timeout_ms(timeout_ms),
	m_stopped(false)
{
	clear();
}

mesos_collector::~mesos_collector()
{
}

void mesos_collector::clear()
{
	FD_ZERO(&m_errfd);
	FD_ZERO(&m_infd);
}

void mesos_collector::add(std::shared_ptr<mesos_http> handler)
{
	int sockfd = handler->get_watch_socket(5000L);

	FD_SET(sockfd, &m_errfd);
	FD_SET(sockfd, &m_infd);
	if(sockfd > m_nfds)
	{
		m_nfds = sockfd;
	}
	m_sockets[sockfd] = handler;
	m_subscription_count = m_sockets.size();
}

void mesos_collector::remove(socket_map_t::iterator it)
{
	if(it != m_sockets.end())
	{
		m_sockets.erase(it);
	}
	m_nfds = 0;
	for (auto& sock : m_sockets)
	{
		if(sock.first > m_nfds)
		{
			m_nfds = sock.first;
		}
	}

	m_subscription_count = m_sockets.size();
}

void mesos_collector::remove_all()
{
	clear();
	for (socket_map_t::iterator it = m_sockets.begin(); it != m_sockets.end();)
	{
		remove(it++);
	}
}

bool mesos_collector::is_active() const
{
	return m_sockets.size() > 0;
}

int mesos_collector::subscription_count() const
{
	return m_subscription_count;
}

void mesos_collector::get_data()
{
	try
	{
		struct timeval tv;
		int res;
		m_stopped = false;
		while (!m_stopped)
		{
			tv.tv_sec  = m_loop ? m_timeout_ms / 1000 : 0;
			tv.tv_usec = m_loop ? (m_timeout_ms % 1000) * 1000 : 0;
			{
				if(m_sockets.size())
				{
					res = select(m_nfds + 1, &m_infd, NULL, &m_errfd, &tv);
					if(res < 0) // error
					{
						std::string err = strerror(errno);
						g_logger.log(err, sinsp_logger::SEV_CRITICAL);
						remove_all();
					}
					else // data or idle
					{
						for (auto& sock : m_sockets)
						{
							if(FD_ISSET(sock.first, &m_infd))
							{
								if(!sock.second->on_data())
								{
									remove(m_sockets.find(sock.first));
								}
							}
							else
							{
								FD_SET(sock.first, &m_infd);
							}

							if(FD_ISSET(sock.first, &m_errfd))
							{
								std::string err = strerror(errno);
								g_logger.log(err, sinsp_logger::SEV_CRITICAL);
								sock.second->on_error(err, true);
								remove(m_sockets.find(sock.first));
							}
							else
							{
								FD_SET(sock.first, &m_errfd);
							}
						}
					}
				}
				else
				{
					g_logger.log("Collector is empty. Stopping.", sinsp_logger::SEV_ERROR);
					m_stopped = true;
					return;
				}
			}
			if(!m_loop)
			{
				break;
			}
		}
	}
	catch(std::exception& ex)
	{
		g_logger.log(std::string("Collector error: ") + ex.what(), sinsp_logger::SEV_ERROR);
		remove_all();
		m_stopped = true;
	}
}


#endif // HAS_CAPTURE
