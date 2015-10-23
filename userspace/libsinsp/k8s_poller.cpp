//
// k8s_poller.cpp
//


#include "sinsp.h"
#include "sinsp_int.h"
#include "k8s_poller.h"
#include "k8s_http.h"
#include <unistd.h>
#include <string.h>
#include <sstream>

k8s_poller::k8s_poller(bool do_loop, long timeout_ms): m_nfds(0),
	m_loop(do_loop),
	m_timeout_ms(timeout_ms),
	m_stopped(false)
{
	remove_all();
}

k8s_poller::~k8s_poller()
{
}

void k8s_poller::add(k8s_http* handler)
{
	K8S_LOCK_GUARD_MUTEX;

	int sockfd = handler->get_watch_socket(5000L);

	FD_SET(sockfd, &m_errfd);
	FD_SET(sockfd, &m_infd);
	if(sockfd > m_nfds)
	{
		m_nfds = sockfd;
	}
	m_sockets[sockfd] = handler;
}

void k8s_poller::remove(int sockfd)
{
	K8S_LOCK_GUARD_MUTEX;

	socket_map_t::iterator it = m_sockets.find(sockfd);
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
}

void k8s_poller::remove_all()
{
	K8S_LOCK_GUARD_MUTEX;

	FD_ZERO(&m_errfd);
	FD_ZERO(&m_infd);
	m_sockets.clear();
}

bool k8s_poller::is_active() const
{
	K8S_LOCK_GUARD_MUTEX;
	return m_sockets.size() > 0;
}

int k8s_poller::subscription_count() const
{
	K8S_LOCK_GUARD_MUTEX;
	return static_cast<int>(m_sockets.size());
}

void k8s_poller::poll()
{
	struct timeval tv;
	int res;

	while (!m_stopped)
	{
		tv.tv_sec  = m_loop ? m_timeout_ms / 1000 : 0;
		tv.tv_usec = m_loop ? (m_timeout_ms % 1000) * 1000 : 0;
		{
			K8S_LOCK_GUARD_MUTEX;

			if(m_sockets.size())
			{
				res = select(m_nfds + 1, &m_infd, NULL, &m_errfd, &tv);
				if(res < 0) // error
				{
					g_logger.log(strerror(errno), sinsp_logger::SEV_CRITICAL);
					remove_all();
				}
				else // data or idle
				{
					for (auto& sock : m_sockets)
					{
						if(FD_ISSET(sock.first, &m_infd))
						{
							sock.second->on_data();
						}
						else
						{
							FD_SET(sock.first, &m_infd);
						}

						if(FD_ISSET(sock.first, &m_errfd))
						{
							sock.second->on_error();
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
				g_logger.log("Poller is empty.", sinsp_logger::SEV_ERROR);
			}
		}
		if(!m_loop)
		{
			break;
		}
		sleep(1);
	}
}
