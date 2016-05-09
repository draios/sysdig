//
// k8s_collector.cpp
//

#ifdef HAS_CAPTURE

#include "sinsp.h"
#include "sinsp_int.h"
#include "k8s_collector.h"
#include "k8s_http.h"
#include <string.h>
#include <sstream>
#include <unistd.h>


k8s_collector::k8s_collector(bool do_loop, long timeout_ms): m_subscription_count(0),
	m_nfds(0),
	m_loop(do_loop),
	m_timeout_ms(timeout_ms),
	m_stopped(false)
{
	clear();
}

k8s_collector::~k8s_collector()
{
}

void k8s_collector::clear()
{
	FD_ZERO(&m_errfd);
	FD_ZERO(&m_infd);
}

void k8s_collector::add(k8s_http* handler)
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

void k8s_collector::remove(socket_map_t::iterator& it)
{
	if(it != m_sockets.end())
	{
		m_sockets.erase(it++);
	}
	m_nfds = 0;
	for(const auto& sock : m_sockets)
	{
		if(sock.first > m_nfds)
		{
			m_nfds = sock.first;
		}
	}
	m_subscription_count = m_sockets.size();
}

void k8s_collector::remove_all()
{
	clear();
	m_sockets.clear();
	m_nfds = 0;
	m_subscription_count = 0;
}

bool k8s_collector::is_active() const
{
	return m_sockets.size() > 0;
}

int k8s_collector::subscription_count() const
{
	return m_subscription_count;
}

void k8s_collector::get_data()
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
						g_logger.log(err, sinsp_logger::SEV_ERROR);
						remove_all();
					}
					else // data or idle
					{
						for(socket_map_t::iterator it = m_sockets.begin(); it != m_sockets.end();)
						{
							if(FD_ISSET(it->first, &m_infd))
							{
								if(it->second && !it->second->on_data())
								{
									if(errno != EAGAIN)
									{
										remove(it);
										continue;
									}
								}
							}
							else
							{
								FD_SET(it->first, &m_infd);
							}

							if(FD_ISSET(it->first, &m_errfd))
							{
								if(errno != EAGAIN)
								{
									std::string err = strerror(errno);
									g_logger.log(err, sinsp_logger::SEV_ERROR);
									it->second->on_error(err, true);
									remove(it);
									continue;
								}
							}
							else
							{
								FD_SET(it->first, &m_errfd);
							}
							++it;
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
