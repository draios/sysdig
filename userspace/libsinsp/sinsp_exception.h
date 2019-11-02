/*
Copyright (C) 2013-2019 Sysdig Inc.

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
#pragma once

#include <stdexcept>
#include <string>

/*!
  \brief sinsp library exception.
*/
class sinsp_exception : public std::runtime_error
{
public:
	sinsp_exception(const std::string& error_str):
		std::runtime_error(error_str),
		m_scap_rc(0)
	{ }

	sinsp_exception(const char* const error_str):
		std::runtime_error(error_str),
		m_scap_rc(0)
	{ }

	sinsp_exception(const std::string& error_str, const int32_t scap_rc):
		std::runtime_error(error_str),
		m_scap_rc(scap_rc)
	{ }

	int32_t scap_rc() const
	{
		return m_scap_rc;
	}

private:
	int32_t m_scap_rc;
};
