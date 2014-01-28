#pragma once

#ifdef HAS_CHISELS

namespace Json {
	class Value;
}

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

/*!
  \brief This is the class that compiles and runs sysdig-type filters.
*/
typedef struct chiseldir_info
{
	bool m_need_to_resolve;
	char m_dir[1024];
}chiseldir_info;

class chiselarg_desc
{
public:
	chiselarg_desc(string name, string type, string description)
	{
		m_name = name;
		m_type = type;
		m_description = description;
	}

	string m_name;
	string m_type;
	string m_description;
};

class chisel_desc
{
public:
	string m_name;
	string m_description;
	vector<chiselarg_desc> m_args;
};


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

class SINSP_PUBLIC chisel
{
public:
	chisel(sinsp* inspector, string filename);
	~chisel();
	static void get_chisel_list(vector<chisel_desc>* chisel_descs);
	void load(string cmdstr);
	uint32_t get_n_args();
	void set_args(vector<string>* argvals);
	void run(sinsp_evt* evt);

private:
	bool openfile(string filename, OUT ifstream* is);

	sinsp* m_inspector;
	string m_description;
	Json::Value* m_root;
	vector<chiselinfo*> m_subchisels;
	vector<string> m_argvals;
	string m_filename;
};

/*@}*/

#endif // HAS_CHISELS

