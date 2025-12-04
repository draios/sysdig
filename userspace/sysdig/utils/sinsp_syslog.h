#pragma once

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_exception.h>

#include <stdint.h>
#include <string>
#include <memory>

class sinsp_syslog_decoder {
public:
	void parse_data(const char* data, uint32_t len);

	std::string get_info_line() const;
	std::string get_severity_str() const;
	std::string get_facility_str() const;

	inline void reset() { m_priority = s_invalid_priority; }

	bool is_data_valid() const { return m_priority != s_invalid_priority; }

	inline int32_t get_priority() const { return m_priority; }

	inline uint32_t get_facility() const { return m_facility; }

	inline uint32_t get_severity() const { return m_severity; }

	inline const std::string& get_msg() const { return m_msg; }

    void parse(sinsp_evt* evt);

private:
	void decode_message(const char* data, uint32_t len, char* pristr, uint32_t pristrlen);

	int32_t m_priority{s_invalid_priority};
	uint32_t m_facility{0};
	uint32_t m_severity{0};
	std::string m_msg;
	std::string m_infostr;

	static constexpr const int32_t s_invalid_priority = -1;
};
