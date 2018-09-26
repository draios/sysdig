/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

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

#include <cstddef>

#include "sinsp.h"
#include "utils.h"
#include "token_bucket.h"

token_bucket::token_bucket()
{
	init(1, 1);
}

token_bucket::~token_bucket()
{
}

void token_bucket::init(double rate, double max_tokens, uint64_t now)
{
	m_rate = rate;
	m_max_tokens = max_tokens;
	m_tokens = max_tokens;

	if(now == 0)
	{
		now = sinsp_utils::get_current_time_ns();
	}

	m_last_seen = now;
}

bool token_bucket::claim()
{
	uint64_t now = sinsp_utils::get_current_time_ns();

	return claim(1, now);
}

bool token_bucket::claim(double tokens, uint64_t now)
{
	double tokens_gained = m_rate * ((now - m_last_seen) / (1000000000.0));
	m_last_seen = now;

	m_tokens += tokens_gained;

	//
	// Cap at max_tokens
	//
	if(m_tokens > m_max_tokens)
	{
		m_tokens = m_max_tokens;
	}

	//
	// If m_tokens is < tokens, can't claim.
	//
	if(m_tokens < tokens)
	{
		return false;
	}

	m_tokens -= tokens;

	return true;
}

double token_bucket::get_tokens()
{
	return m_tokens;
}

uint64_t token_bucket::get_last_seen()
{
	return m_last_seen;
}
