/*
Copyright (C) 2013-2021 Sysdig Inc.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

//
// Plugin Directory info
//
class insight_info
{
public:
	enum severity
	{
		SEV_DEBUG = 0,
		SEV_INFO = 1,
		SEV_LOW = 2,
		SEV_MEDIUM = 3,
		SEV_HIGH = 4,
	};

	insight_info(string name,
		string filter,
		string desc,
		severity severity,
		vector<string> keys)
	{
		m_name = name;
		m_filter = filter;
		m_desc = desc;
		m_severity = severity;
		m_keys = keys;
	}

	uint32_t m_id;
	string m_name;
	string m_filter;
	string m_desc;
	severity m_severity;
	vector<string> m_keys;
};

class insights_runner
{
public:
	insights_runner(sinsp* inspector);
	void add(insight_info info);
	vector<uint32_t>* run(sinsp_evt* evt);
	void print();

private:
	vector <insight_info> m_infos;
	vector <sinsp_filter*> m_filters;
	sinsp* m_inspector = NULL;
	// This is used to return the result of run() without allocating a vector every
	// time run is called.
	vector<uint32_t> m_runres;
};
