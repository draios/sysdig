#include <fstream>

#include <sinsp.h>
#include <user_event.h>
#include <logger.h>

#include "json_error_log.h"

json_error_log g_json_error_log;

json_error_log::json_error_log()
	: m_events_rate(.00333), // one event per 5 minutes
	  m_events_max_burst(10)
{
}

json_error_log::~json_error_log()
{
}

void json_error_log::set_json_parse_errors_file(const std::string& filename)
{
	m_json_parse_errors_file = filename;
}

// Note: not changing the rate/burst of any already-created bucket
void json_error_log::set_events_rate(double events_rate, uint32_t max_burst)
{
	m_events_rate = events_rate;
	m_events_max_burst = max_burst;
}

void json_error_log::log(const std::string &json, const std::string &errstr,
			 uint64_t ts_ns, const std::string &uri)
{
	time_t now = ts_ns / ONE_SECOND_IN_NS;

	if(m_json_parse_errors_file != "")
	{
		std::ofstream errs(m_json_parse_errors_file, std::ofstream::out | std::ofstream::app);
		char buf[sizeof("YYYY-MM-DDTHH:MM:SSZ")];
		strftime(buf, sizeof(buf), "%FT%TZ", gmtime(&now));

		errs << "*******************************" << std::endl;
		errs << "URI: " << uri << std::endl;
		errs << "Time (UTC): " << buf << std::endl;
		errs << "Error: " << errstr << std::endl;
		errs << "Json: " << json << std::endl;
		errs << "*******************************" << std::endl;

		errs.close();
	}

	token_bucket &bucket = get_bucket(uri);

	if(bucket.claim(1, ts_ns))
	{
		sinsp_user_event evt;
		sinsp_user_event::tag_map_t tags;
		tags["source"] = "json_parser";
		tags["uri"] = uri;
		tags["json_prefix"] = json.substr(0, 100);
		std::string event_name = "json_parse_error";
		std::string desc = errstr;

		event_scope scope;
		if(m_machine_id.length())
		{
			scope.add("host.mac", m_machine_id);
		}

		// Also emit a custom event noting the json parse failure.
		std::string evtstr = sinsp_user_event::to_string(now,
								 std::move(event_name),
								 std::move(desc),
								 std::move(scope),
								 std::move(tags));

		g_logger.log("Logging user event: " + evtstr, sinsp_logger::SEV_DEBUG);

		g_logger.log(evtstr, sinsp_logger::SEV_EVT_WARNING);
	}
}

token_bucket &json_error_log::get_bucket(const std::string &uri)
{
	auto it = m_buckets.lower_bound(uri);

	if(it == m_buckets.end() ||
	   it->first != uri)
	{
		it = m_buckets.emplace_hint(it,
					    std::make_pair(uri, token_bucket()));

		it->second.init(m_events_rate, m_events_max_burst);
	}

	return it->second;
}

