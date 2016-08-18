//
// socket_collector.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "socket_handler.h"

template <typename T>
class socket_collector
{
public:
	typedef std::map<int, std::shared_ptr<T>> socket_map_t;

	socket_collector(bool do_loop = true, long timeout_ms = 1000L):
		m_nfds(0),
		m_loop(do_loop),
		m_timeout_ms(timeout_ms),
		m_stopped(false)
	{
		clear();
	}

	~socket_collector()
	{
	}

	void add(std::shared_ptr<T> handler)
	{
		int sockfd = handler->get_socket(m_timeout_ms);

		FD_SET(sockfd, &m_errfd);
		FD_SET(sockfd, &m_infd);
		if(sockfd > m_nfds)
		{
			m_nfds = sockfd;
		}
		m_sockets[sockfd] = handler;
	}

	bool has(std::shared_ptr<T> handler)
	{
		for(const auto& http : m_sockets)
		{
			if(http.second == handler)
			{
				return true;
			}
		}
		return false;
	}

	bool remove(std::shared_ptr<T> handler)
	{
		for(typename socket_map_t::iterator it = m_sockets.begin(); it != m_sockets.end(); ++it)
		{
			if(it->second == handler)
			{
				remove(it);
				return true;
			}
		}
		return false;
	}

	void remove_all()
	{
		clear();
		m_sockets.clear();
		m_nfds = 0;
	}

	int subscription_count() const
	{
		return m_sockets.size();
	}

	void get_data()
	{
		try
		{
			struct timeval tv;
			int res;
			m_stopped = false;
			while(!m_stopped)
			{
				tv.tv_sec  = m_loop ? m_timeout_ms / 1000 : 0;
				tv.tv_usec = m_loop ? (m_timeout_ms % 1000) * 1000 : 0;
				{
					if(m_sockets.size())
					{
						res = select(m_nfds + 1, &m_infd, NULL, &m_errfd, &tv);
						if(res > 0)
						{
							g_logger.log("Socket collector: " + std::to_string(m_sockets.size()) + " sockets total, activity detected on " + 
										std::to_string(res) + " sockets.", sinsp_logger::SEV_DEBUG);
						}
						else if(res == 0)
						{
							g_logger.log("Socket collector: " + std::to_string(m_sockets.size()) + " sockets.", sinsp_logger::SEV_DEBUG);
						}
						if(res < 0) // error
						{
							std::string err = strerror(errno);
							g_logger.log("Socket collector select error, removing all sockets (" + err + ')', sinsp_logger::SEV_ERROR);
							remove_all();
						}
						else // data or idle
						{
							for(typename socket_map_t::iterator it = m_sockets.begin(); it != m_sockets.end();)
							{
								std::string id = it->second->get_id();
								if(FD_ISSET(it->first, &m_infd))
								{
									if(it->second && !it->second->on_data())
									{
										if(errno != EAGAIN)
										{
											g_logger.log("Socket collector data handling error, removing socket for handler [" + id+ ']', sinsp_logger::SEV_ERROR);
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
										std::string fid;
										if(it->second)
										{
											it->second->on_error(err, true);
											g_logger.log("Socket collector: socket error, removing socket for handler [" + id+ ']', sinsp_logger::SEV_ERROR);
										}
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
						g_logger.log("Socket collector is empty. Stopping.", sinsp_logger::SEV_ERROR);
						m_stopped = true;
						return;
					}
				}
				if(!m_loop) { break; }
			}
		}
		catch(std::exception& ex)
		{
			g_logger.log(std::string("Socket collector error: ") + ex.what(), sinsp_logger::SEV_ERROR);
			remove_all();
			m_stopped = true;
		}
	}

	void stop()
	{
		m_stopped = true;
	}

	bool is_active() const
	{
		return subscription_count() > 0;
	}

	bool is_healthy(int expected_count) const
	{
		return subscription_count() >= expected_count;
	}

private:
	void clear()
	{
		FD_ZERO(&m_errfd);
		FD_ZERO(&m_infd);
	}

	typename socket_map_t::iterator& remove(typename socket_map_t::iterator& it)
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
		return it;
	}

	socket_map_t     m_sockets;
	fd_set           m_infd;
	fd_set           m_errfd;
	int              m_nfds;
	bool             m_loop;
	long             m_timeout_ms;
	bool             m_stopped;
};

#endif // HAS_CAPTURE
