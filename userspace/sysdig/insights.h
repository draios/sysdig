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
		SEV_LOW = 0,
		SEV_MED = 1,
		SEV_HI = 2,
	};

    insight_info(string name, string filter, string desc, severity severity)
    {
        m_name = name;
        m_filter = filter;
        m_desc = desc;
        m_severity = severity;
    }

    uint32_t m_id;
    string m_name;
    string m_filter;
    string m_desc;
    severity m_severity;
};

class insights_runner
{
public:
    insights_runner(sinsp* inspector);
    void add(insight_info info);
    vector<uint32_t>* run(sinsp_evt* evt);
    vector <insight_info>* list();

private:
    vector <insight_info> m_infos;
    vector <sinsp_filter*> m_filters;
	sinsp* m_inspector = NULL;
	// This is used to return the result of run() without allocating a vector every
	// time run is called.
	vector<uint32_t> m_runres;
};
