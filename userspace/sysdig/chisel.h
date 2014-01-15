#pragma once

#include <json/json.h>

class chiselinfo
{
public:
	chiselinfo();
	void init(sinsp* inspector, string filterstr, string formatterstr); 
	~chiselinfo();
	sinsp_filter* m_filter;
	sinsp_evt_formatter* m_formatter;
	sinsp_dumper* m_dumper;
};

class chisel
{
public:
	chisel(sinsp* inspector, string filename);
	~chisel();
	void load(string cmdstr);
	uint32_t get_n_args();
	void set_args(vector<string>* argvals);
	void run(sinsp_evt* evt);

private:
	sinsp* m_inspector;
	string m_description;
	Json::Value m_root;
	vector<chiselinfo*> m_subchisels;
	vector<string> m_argvals;
	string m_filename;
};