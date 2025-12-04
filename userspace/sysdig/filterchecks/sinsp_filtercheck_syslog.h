#pragma once

#include <libsinsp/sinsp_filtercheck.h>
#include "../utils/sinsp_syslog.h"

class sinsp_filter_check_syslog : public sinsp_filter_check {
public:
	enum check_type {
		TYPE_FACILITY_STR = 0,
		TYPE_FACILITY,
		TYPE_SEVERITY_STR,
		TYPE_SEVERITY,
		TYPE_MESSAGE,
	};

	sinsp_filter_check_syslog(std::shared_ptr<sinsp_syslog_decoder> syslog_decoder);
	virtual ~sinsp_filter_check_syslog() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;

protected:
	uint8_t* extract_single(sinsp_evt*, uint32_t* len, bool sanitize_strings = true) override;

private:
	uint32_t m_storageu32;
	std::string mstrstorage;
	std::shared_ptr<sinsp_syslog_decoder> m_syslog_decoder;
};
