#pragma once

class sinsp_filter_check;

class SINSP_PUBLIC sinsp_evt_formatter
{
public:
	sinsp_evt_formatter(sinsp* inspector, const string& fmt);
	//
	// Fills res with the string rendering of the event.
	// Returns true if the string should be shown (based on the initial *).
	//
	bool tostring(sinsp_evt* evt, OUT string* res);

private:
	void set_format(const string& fmt);
	vector<sinsp_filter_check*> m_tokens;
	sinsp* m_inspector;
	bool m_require_all_values;
};
