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
	add(insight_info("EC2 instance run", "ct.name=RunInstances", "new EC2 instance started", insight_info::SEV_LOW, {"ct.user", "ct.region", "ct.srcip", "ct.error"}));
	add(insight_info("infrastructure modifying event", "ct.readonly=false", "actions that modify the state of the AWS environment", insight_info::SEV_DEBUG, {"ct.shortsrc", "ct.name", "ct.user", "ct.region" "ct.error"}));
	add(insight_info("EC2 modifying events", "ct.shortsrc=ec2 and ct.readonly=false", "actions that modify the state of the state of the EC2 infrastructure", insight_info::SEV_INFO, {"ct.shortsrc", "ct.user", "ct.region" "ct.error"}));
	add(insight_info("s3 modifying events", "ct.shortsrc=s3 and ct.readonly=false", "actions that modify the state of the state of the s3 infrastructure", insight_info::SEV_INFO, {"ct.shortsrc", "ct.user", "ct.region" "ct.error"}));
	add(insight_info("console login", "ct.name = ConsoleLogin", "An user logged in to the console", insight_info::SEV_INFO, {"ct.user", "ct.region", "ct.srcip", "ct.error"}));
	add(insight_info("S3 bucket became public", "ct.name = PutBucketPublicAccessBlock and ct.info contains BlockPublicAcls=false and ct.info contains BlockPublicPolicy=false and ct.info contains IgnorePublicAcls=false and ct.info contains RestrictPublicBuckets=false", "all public blocks were removed from an s3 bucket", insight_info::SEV_HIGH, {"s3.bucket", "ct.user", "ct.region", "ct.srcip"}));
	add(insight_info("EC2 KeyPair operation", "ct.shortsrc = ec2 and ct.readonly = false and ct.name contains KeyPair", "Stored EC2 KeyPairs were modified", insight_info::SEV_INFO, {"ct.user", "ct.srcip", "ct.error"}));
	add(insight_info("CloudTrail log started", "ct.shortsrc = cloudtrail and ct.name = StartLogging", "CloudTrail log stopped", insight_info::SEV_INFO, {"ct.request.name", "ct.user", "ct.region", "ct.error"})); // missing fields in the event
	add(insight_info("CloudTrail log stopped", "ct.shortsrc = cloudtrail and ct.name = StopLogging", "CloudTrail log stopped", insight_info::SEV_LOW, {"ct.request.name", "ct.user", "ct.region", "ct.error"})); // missing fields in the event
	add(insight_info("CloudTrail logs stored in s3 accessed", "s3.uri contains /CloudTrail/ and ct.user.identitytype != AWSService", "access performed to stored cloudtrail logs (uploaded, downloaded, modified) from an entity outside AWS Services", insight_info::SEV_INFO, {"s3.bucket", "ct.user", "ct.region", "ct.srcip", "ct.error"}));
	add(insight_info("list buckets", "ct.name=ListBuckets", "attempts to list the s3 buckets", insight_info::SEV_MEDIUM, {"ct.user", "ct.region", "ct.srcip", "ct.error"}));
	add(insight_info("failed event", "not ct.error exists", "cloudtrail commands that failed", insight_info::SEV_DEBUG, {"ct.name", "ct.user", "ct.region", "ct.srcip"}));
	add(insight_info("failed infrastructure modifying event", "not ct.error exists and ct.readonly=false", "actions that modify the state of the AWS environment but failed", insight_info::SEV_INFO, {"ct.name", "ct.user", "ct.region", "ct.srcip"}));
	add(insight_info("create bucket", "ct.name=CreateBucket", "attempts to create an s3 bucket", insight_info::SEV_MEDIUM, {"s3.bucket", "ct.user", "ct.region", "ct.error"}));
	add(insight_info("delete bucket", "ct.name=DeleteBucket", "attempts to delete an s3 bucket", insight_info::SEV_MEDIUM, {"s3.bucket", "ct.user", "ct.region", "ct.error"}));
	add(insight_info("change in bucket policy", "ct.name=PutBucketPolicy or ct.name=PutBucketPublicAccessBlock", "attempts to change the policy settings of an s3 bucket", insight_info::SEV_MEDIUM, {"s3.bucket", "ct.user", "ct.region", "ct.error"}));
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

void insights_runner::print()
{
	printf("\n[");
	for(uint32_t j = 0; j < m_infos.size(); j++)
	{
		insight_info* ii = &m_infos[j];
		string sevstr = "";
		if(ii->m_severity == insight_info::SEV_DEBUG)
		{
			sevstr = "DEBUG";
		}
		else if(ii->m_severity == insight_info::SEV_INFO)
		{
			sevstr = "INFO";
		}
		else if(ii->m_severity == insight_info::SEV_LOW)
		{
			sevstr = "LOW";
		}
		else if(ii->m_severity == insight_info::SEV_MEDIUM)
		{
			sevstr = "MEDIUM";
		}
		else if(ii->m_severity == insight_info::SEV_HIGH)
		{
			sevstr = "HIGH";
		}
		else
		{
			throw sinsp_exception("insight " + ii->m_name + " has an invalid severity");
		}

		string skeys = "[";
		for(uint32_t k = 0; k < ii->m_keys.size(); k++) {
			skeys += "\"" + ii->m_keys[k] + "\"";
			if(k < ii->m_keys.size() - 1)
			{
				skeys += ",";
			}
		}
		skeys += "]";

		printf("\n{\"id\": %" PRIu32 ", \"name\":\"%s\", \"filter\":\"%s\", \"description\":\"%s\", \"severity\":\"%s\", \"keys\":%s}",
			ii->m_id,
			ii->m_name.c_str(),
			ii->m_filter.c_str(),
			ii->m_desc.c_str(),
			sevstr.c_str(),
			skeys.c_str());
		if(j < m_infos.size() - 1)
		{
			printf(",");
		}
	}
	printf("\n]\n");
}
