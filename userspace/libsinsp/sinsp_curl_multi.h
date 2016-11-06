//
// Created by Luca Marturana on 14/10/2016.
//

#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_curl.h"
#include <curl/multi.h>

class sinsp_curl_multi
{
public:
	sinsp_curl_multi();
	~sinsp_curl_multi();

	void add(shared_ptr<sinsp_curl> easy);

	void remove(shared_ptr<sinsp_curl> easy);

	void run();

private:
	vector<shared_ptr<sinsp_curl>> m_easy_handles;
	CURLM *m_cm;
	int m_running_tasks;

	vector<shared_ptr<sinsp_curl>>::iterator find_by_curle(CURL* ptr);
};
