//
// Created by Luca Marturana on 14/10/2016.
//

#include "sinsp_curl_multi.h"

sinsp_curl_multi::sinsp_curl_multi():
	m_running_tasks(0)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	m_cm = curl_multi_init();
}

sinsp_curl_multi::~sinsp_curl_multi()
{
	curl_multi_cleanup(m_cm);
	curl_global_cleanup();
}

void sinsp_curl_multi::add(shared_ptr<sinsp_curl> easy)
{
	curl_multi_add_handle(m_cm, easy->m_curl);
	m_easy_handles.emplace_back(move(easy));
	m_running_tasks += 1;
}

void sinsp_curl_multi::run()
{
	if(m_running_tasks == 0)
	{
		return;
	}
	cerr << __FUNCTION__ << ":" << __LINE__ << "tasks=" << m_running_tasks << endl;
	curl_multi_perform(m_cm, &m_running_tasks);
	if(m_running_tasks < static_cast<int>(m_easy_handles.size()))
	{
		CURLMsg *msg;
		int queued_messages;
		while((msg = curl_multi_info_read(m_cm, &queued_messages)))
		{
			if(msg->msg == CURLMSG_DONE)
			{
				cerr << __FUNCTION__ << ":" << __LINE__ << endl;
				auto curl_handle_it = find_by_curle(msg->easy_handle);
				if (curl_handle_it != m_easy_handles.end())
				{
					auto m_curl_easy = *curl_handle_it;
					m_easy_handles.erase(curl_handle_it);
					cerr << __FUNCTION__ << ":" << __LINE__ << "ended request=" << (*curl_handle_it)->m_uri.to_string(false) << endl;
					curl_multi_remove_handle(m_cm, msg->easy_handle);
					m_curl_easy->m_done_callback();
				}
				else
				{
					cerr << __FUNCTION__ << ":" << __LINE__ << endl;
				}
			}
		}
	}
}

vector<shared_ptr<sinsp_curl>>::iterator sinsp_curl_multi::find_by_curle(CURL* ptr)
{
	return find_if(m_easy_handles.begin(), m_easy_handles.end(), [ptr](const shared_ptr<sinsp_curl>& easy)
	{
		return ptr == easy->m_curl;
	});
}