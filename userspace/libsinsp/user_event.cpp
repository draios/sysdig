/*
Copyright (C) 2013-2014 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "sinsp.h"
#include "sinsp_int.h"
#include "user_event.h"

//
// event_scope
//

const std::string event_scope::SCOPE_OP_AND = "and";

// these string lists contain reserved strings; some of the reserved
// strings are escaped and mandatory to be first in RESERVED_STRINGS
// and have their escaped counterparts in the REPLACEMENT_STRINGS,
// in the same order as they appear in RESERVED_STRINGS
const event_scope::string_list_t event_scope::RESERVED_STRINGS =
	{"'"};
const event_scope::string_list_t event_scope::REPLACEMENT_STRINGS =
	{"\\'"};

// scope key name format regex
#ifndef _WIN32
const std::string event_scope::KEY_FORMAT = "[a-zA-Z0-9_/\\.-]*";
#else
const std::string event_scope::KEY_FORMAT = "^[a-zA-Z0-9_/\\.-]*$";
#endif // _WIN32

event_scope::event_scope(const std::string& key, const std::string& value)
{
	if(!key.empty() && !value.empty())
	{
		add(key, value, "");
	}
}

bool event_scope::add(const std::string& key, const std::string& value, const std::string& op)
{
	if(check_key_format(key))
	{
		std::string k(key);
		std::string o(!m_scope.empty() ? op : "");
		std::string v(value);
		replace(v);
		if(!v.empty())
		{
			if(!o.empty())
			{
				m_scope.append(1, ' ').append(trim(o)).append(1, ' ');
			}
			m_scope.append(trim(k)).append("='").append(trim(v)).append(1, 0x27);
			return true;
		}
	}
	else
	{
		g_logger.log("Scope key is invalid: [" + key + "], entry will not be added to scope.",
					 sinsp_logger::SEV_WARNING);
	}
	return false;
}

string& event_scope::replace(std::string& value)
{
	ASSERT(RESERVED_STRINGS.size() == REPLACEMENT_STRINGS.size());

	string_list_t::const_iterator res_it = RESERVED_STRINGS.cbegin();
	string_list_t::const_iterator res_end = RESERVED_STRINGS.cend();
	string_list_t::const_iterator rep_it = REPLACEMENT_STRINGS.cbegin();
	string_list_t::const_iterator rep_end = REPLACEMENT_STRINGS.cend();
	for(; res_it != res_end && rep_it != rep_end; ++res_it, ++rep_it)
	{
		replace_in_place(value, *res_it, *rep_it);
	}

	return value;
}

#ifndef _WIN32
void event_scope::regex_error(const std::string& call, size_t ret, regex_t* preg, const std::string& str)
{
	if(!preg) { return; }
	char errbuf[256] = {0};
	if(regerror(ret, preg, errbuf, 256))
	{
		g_logger.log(call + "() error: " + errbuf, sinsp_logger::SEV_WARNING);
	}
	else
	{
		g_logger.log("Can't obtain " + call + "() [" + str + "] error.", sinsp_logger::SEV_WARNING);
	}
}

bool event_scope::check_key_format(const std::string& key)
{

	if(key.empty()) { return false; }
	bool result = false;
	std::string exp(KEY_FORMAT);
	regex_t reg = {0};
	size_t ret = regcomp(&reg, exp.c_str(), REG_EXTENDED);
	if(0 == ret)
	{
		regmatch_t rm = {0};
		ret = regexec(&reg, key.c_str(), 1, &rm, 0);
		if(0 == ret)
		{
			if((rm.rm_eo - rm.rm_so) == static_cast<regoff_t>(key.length()))
			{
				result = true;
			}
		}
		else { regex_error("regexec", ret, &reg, key); }
	}
	else { regex_error("regcomp", ret, &reg, exp); }
	regfree(&reg);
	return result;
}

#else

bool event_scope::check_key_format(const std::string& key)
{
	static const std::regex r(KEY_FORMAT);
	if (std::regex_match(key, r)) { return true; }
	return false;
}

#endif // _WIN32

//
// user_event_meta_t
//
const std::string user_event_meta_t::PERMIT_ALL = "all";

user_event_meta_t::user_event_meta_t(const std::string& kind, const type_list_t& types):
	m_kind(kind), m_types(types)
{
}

user_event_meta_t::user_event_meta_t(std::string&& kind, type_list_t&& types):
	m_kind(std::move(kind)), m_types(std::move(types))
{
}

user_event_meta_t::user_event_meta_t(const user_event_meta_t& other):
	m_kind(other.m_kind), m_types(other.m_types)
{
}

user_event_meta_t::user_event_meta_t(user_event_meta_t&& other):
	m_kind(std::move(other.m_kind)), m_types(std::move(other.m_types))
{
	other.m_kind.clear();
	other.m_types.clear();
}

user_event_meta_t& user_event_meta_t::operator = (const user_event_meta_t& other)
{
	if(&other != this)
	{
		m_kind = other.m_kind;
		m_types = other.m_types;
	}
	return *this;
}

user_event_meta_t& user_event_meta_t::operator = (user_event_meta_t&& other)
{
	if(&other != this)
	{
		m_kind = std::move(other.m_kind);
		m_types = std::move(other.m_types);
		other.m_kind.clear();
		other.m_types.clear();
	}
	return *this;
}

//
// user_event_filter_t
//
user_event_filter_t::user_event_filter_t()
{
}

user_event_filter_t::user_event_filter_t(const list_t& list): m_list(list)
{
}

user_event_filter_t::user_event_filter_t(list_t&& list): m_list(std::move(list))
{
}

void user_event_filter_t::add(const user_event_meta_t& evt)
{
	if(handle_all(user_event_meta_t(evt)))
	{
		return;
	}
	if(get_meta(evt.kind()) == m_list.end())
	{
		m_list.insert(evt);
	}
}

void user_event_filter_t::add(user_event_meta_t&& evt)
{
	if(handle_all(user_event_meta_t(evt)))
	{
		return;
	}
	if(get_meta(evt.kind()) == m_list.end())
	{
		m_list.emplace(std::move(evt));
	}
}

bool user_event_filter_t::handle_all(user_event_meta_t&& evt)
{
	if(ci_compare_str(evt.kind(), user_event_meta_t::PERMIT_ALL))
	{
		m_list.clear();
		m_list.emplace(std::move(evt));
		return true;
	}
	user_event_meta_t loc_evt(evt);
	list_t::iterator it = m_list.find(loc_evt);
	if(it != m_list.end())
	{
		if(it->types().find(user_event_meta_t::PERMIT_ALL) != it->types().end())
		{
			m_list.erase(it);
			m_list.insert(loc_evt);
			return true;
		}
	}
	return false;
}

void user_event_filter_t::remove(const user_event_meta_t& evt)
{
	m_list.erase(evt);
}

void user_event_filter_t::remove(const std::string& kind)
{
	user_event_meta_t::type_list_t types;
	user_event_meta_t evt(kind, types);
	remove(evt);
}

user_event_filter_t::list_t::const_iterator user_event_filter_t::get(const std::string& evt_kind) const
{
	list_t::const_iterator it = m_list.begin(), end = m_list.end();
	for(;it != end; ++it)
	{
		if(ci_compare_str(it->kind(), evt_kind)) { return it; }
	}
	return end;
}

bool user_event_filter_t::has(const std::string& evt_kind, const std::string& evt_type) const
{
	list_t::const_iterator it = get(evt_kind);
	if(it != m_list.end())
	{
		for(const auto& t : it->types())
		{
			if(ci_compare_str(t, evt_type))
			{
				return true;
			}
		}
	}
	return false;
}

bool user_event_filter_t::allows(const user_event_meta_t& evt) const
{
	list_t::const_iterator it = get_meta(evt.kind());
	if(it != m_list.end()) // this event kind is allowed
	{
		// check for "any event" type being allowed by this filter
		if(it->types().find(user_event_meta_t::PERMIT_ALL) != it->types().end())
		{
			return true;
		}
		// check if event has more types than this filter
		if(evt.types().size() > it->types().size())
		{
			return false;
		}
		// if all event types are present in this filter, event is allowed
		for(auto const& type : evt.types())
		{
			if(it->types().find(type) == it->types().end())
			{
				return false;
			}
		}
		return true;
	}
	return false;
}

user_event_filter_t::list_t::const_iterator user_event_filter_t::get_meta(const std::string& evt_kind) const
{
	list_t::const_iterator it = m_list.begin(), end = m_list.end();
	for(; it != end; ++it)
	{
		if(ci_compare_str(it->kind(), user_event_meta_t::PERMIT_ALL) || ci_compare_str(it->kind(),evt_kind))
		{
			return it;
		}
	}
	return end;
}

std::string user_event_filter_t::to_string() const
{
	std::string ret;
	for(const auto& evt : m_list)
	{
		if(evt.types().size())
		{
			ret.append(1, '\n').append(evt.kind()).append(1, ':');
			for(const auto& type : evt.types())
			{
				ret.append(type).append(", ");
			}
		}
	}
	return ret;
}

//
// sinsp_user_event
//

sinsp_user_event::sinsp_user_event() : m_epoch_time_s(0), m_severity(~0)
{
}

sinsp_user_event::sinsp_user_event(uint64_t epoch_time_s, string&& name, string&& desc,
	string&& scope, tag_map_t&& tags, uint32_t sev):
	m_epoch_time_s(epoch_time_s), m_name(std::move(name)), m_description(std::move(desc)),
	m_severity(sev), m_scope(std::move(scope)), m_tags(std::move(tags))
{
}

sinsp_user_event::sinsp_user_event(sinsp_user_event&& other):
	m_epoch_time_s(other.m_epoch_time_s),
	m_name(std::move(other.m_name)),
	m_description(std::move(other.m_description)),
	m_severity(other.m_severity),
	m_scope(std::move(other.m_scope)),
	m_tags(std::move(other.m_tags))
{
}

sinsp_user_event& sinsp_user_event::operator=(sinsp_user_event&& other)
{
	if(this != &other)
	{
		m_epoch_time_s = other.m_epoch_time_s;
		m_name = std::move(other.m_name);
		m_description = std::move(other.m_description);
		m_severity = other.m_severity;
		m_scope = std::move(other.m_scope);
		m_tags = std::move(other.m_tags);
	}

	return *this;
}

std::string sinsp_user_event::to_string(uint64_t timestamp,
										std::string&& name,
										std::string&& description,
										event_scope&& scope,
										tag_map_t&& tags,
										uint32_t sev)
{
	const std::string from("\"");
	const std::string to("\\\"");

	std::ostringstream ostr;
	ostr << "timestamp: " << timestamp << '\n' <<
			"name: \"" << replace_in_place(name, from, to) << "\"\n"
			"description: \"" << replace_in_place(description, from, to) << "\"\n"
			"scope: \"" << replace_in_place(scope.get_ref(), from, to) << "\"\n";

	if(sev != UNKNOWN_SEVERITY)
	{
		ostr << "priority: " << sev << '\n';
	}

	if(tags.size())
	{
		ostr << "tags:";
		for(auto& tag : tags)
		{
			ostr << "\n  \"" << replace(tag.first, from, to) << "\": \""
				<< replace_in_place(tag.second, from, to) << '"';
		}
	}
	ostr << std::flush;
	g_logger.log(ostr.str(), sinsp_logger::SEV_DEBUG);
	return ostr.str();
}

void sinsp_user_event::emit_event_overflow(const std::string& component,
										   const std::string& machine_id,
										   const std::string& source)
{
	std::string event_name = component;
	event_name.append(" Event Limit Exceeded");
	std::ostringstream description;
	description << component << " event limit (" << max_events_per_cycle() <<
				" per second) exceeded. Excess events were discarded.";
	std::string scope;
	if(machine_id.length())
	{
		scope.append("host.mac=").append(machine_id);
	}
	tag_map_t tags{{"source", source}};
	g_logger.log(sinsp_user_event::to_string(get_epoch_utc_seconds_now(), std::move(event_name),
				 description.str(), std::move(scope), std::move(tags)), sinsp_logger::SEV_EVT_WARNING);
}
