//
// k8s_poller.cpp
//

#include "k8s_poller.h"
#include "k8s_http.h"
#include <unistd.h>

k8s_poller::k8s_poller(long timeout_ms): m_nfds(0), m_timeout_ms(timeout_ms), m_stopped(false)
{
	FD_ZERO(&m_errfd);
	FD_ZERO(&m_infd);
}

k8s_poller::~k8s_poller()
{
}

void k8s_poller::add(k8s_http* handler)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	int sockfd = handler->get_watch_socket();

	FD_SET(sockfd, &m_errfd);
	FD_SET(sockfd, &m_infd);
	if (sockfd > m_nfds)
	{
		m_nfds = sockfd;
	}
	m_sockets[sockfd] = handler;
}

void k8s_poller::remove(int sockfd)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	socket_map_t::iterator it = m_sockets.find(sockfd);
	if (it != m_sockets.end())
	{
		m_sockets.erase(it);
	}
	m_nfds = 0;
	for (auto& sock : m_sockets)
	{
		if (sock.first > m_nfds)
		{
			m_nfds = sock.first;
		}
	}
}

void k8s_poller::remove_all()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_sockets.clear();
}

void k8s_poller::poll()
{
	struct timeval tv;
	int res;

	while (!m_stopped)
	{
		tv.tv_sec  = m_timeout_ms / 1000;
		tv.tv_usec = (m_timeout_ms % 1000) * 1000;
	
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (m_sockets.size())
			{
				res = select(m_nfds + 1, &m_infd, NULL, &m_errfd, &tv);

				if(res < 0) // error
				{
					//TODO
				}
				else if (res > 0) // data
				{
					for (auto& sock : m_sockets)
					{
						if (FD_ISSET(sock.first, &m_infd))
						{
							sock.second->on_data();
						}
						else
						{
							FD_SET(sock.first, &m_infd);
						}

						if (FD_ISSET(sock.first, &m_errfd))
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
		}
		sleep(1);
	}
}
