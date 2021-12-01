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

#include <stdio.h>
#include <sys/stat.h>

#include <sinsp.h>
#include "sysdig.h"
#include "insights.h"

insights_runner::insights_runner(sinsp* inspector)
{
	m_inspector = inspector;
	add(insight_info("EC2 instance run", "ct.name=RunInstances", "new EC2 instance started", insight_info::SEV_LOW));
	add(insight_info("infrastructure modifying events", "ct.readonly=false", "actions that modify the state of the AWS environment", insight_info::SEV_DEBUG));
	add(insight_info("EC2 modifying events", "ct.shortsrc=ec2 and ct.readonly=false", "actions that modify the state of the state of the EC2 infrastructure", insight_info::SEV_INFO));
	add(insight_info("s3 modifying events", "ct.shortsrc=s3 and ct.readonly=false", "actions that modify the state of the state of the s3 infrastructure", insight_info::SEV_INFO));
}

void insights_runner::add(insight_info info)
{
	ASSERT(m_inspector != NULL);
	sinsp_filter_compiler compiler(m_inspector, info.m_filter);
	try
	{
		sinsp_filter* filter = compiler.compile();
		m_filters.push_back(filter);
	}
	catch(const sinsp_exception& e)
	{
		throw sinsp_exception(string("insights error: ") + e.what());
	}

	info.m_id = m_infos.size();
	m_infos.push_back(info);
}

vector<uint32_t>* insights_runner::run(sinsp_evt* evt)
{
	m_runres.clear();

	for(uint32_t j = 0; j < m_filters.size(); j++)
	{
		if(m_filters[j]->run(evt))
		{
			m_runres.push_back(j);
		}
	}

	return &m_runres;
}

vector <insight_info>* insights_runner::list()
{
	return &m_infos;
}
