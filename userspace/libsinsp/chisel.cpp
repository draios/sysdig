/*
extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}
*/
#include <iostream>
#include <fstream>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>
#ifndef _WIN32
#include <limits.h>
#include <stdlib.h>
#endif
#include <third-party/tinydir.h>
#include <json/json.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "chisel.h"

#ifdef HAS_CHISELS

const chiseldir_info chisel_dirs[] =
{
	{false, ""}, // file as is
	{false, CHISELS_INSTALLATION_DIR},
	{false, "./"},
	{false, "./chisels/"},
	{true, ""},
	{true, "~/chisels/"},
};

/*
    lua_State *L = lua_open();
 
    luaL_openlibs(L);
 
    if(luaL_dofile(L,"c.lua"))
	{
		string err = lua_tostring(L, -1);
	}
 
    lua_close(L);
*/

///////////////////////////////////////////////////////////////////////////////
// String helpers
///////////////////////////////////////////////////////////////////////////////
//
// trim from start
//
string& ltrim(string &s) 
{
	s.erase(s.begin(), find_if(s.begin(), s.end(), not1(ptr_fun<int, int>(isspace))));
	return s;
}

//
// trim from end
//
string& rtrim(string &s) 
{
	s.erase(find_if(s.rbegin(), s.rend(), not1(ptr_fun<int, int>(isspace))).base(), s.end());
	return s;
}

//
// trim from both ends
//
string& trim(string &s) 
{
	return ltrim(rtrim(s));
}

void replace_in_place(string &s, const string &search, const string &replace)
{
    for(size_t pos = 0; ; pos += replace.length()) 
	{
        // Locate the substring to replace
        pos = s.find(search, pos);
        if(pos == string::npos ) break;
        // Replace by erasing and inserting
        s.erase(pos, search.length());
        s.insert(pos, replace );
    }
}

void replace_in_place(string& str, string& substr_to_replace, string& new_substr) 
{
	size_t index = 0;
	uint32_t nsize = new_substr.size();

	while (true) 
	{
		 index = str.find(substr_to_replace, index);
		 if (index == string::npos) break;

		 str.replace(index, nsize, new_substr);

		 index += nsize;
	}
}

///////////////////////////////////////////////////////////////////////////////
// chiselinfo implementation
///////////////////////////////////////////////////////////////////////////////
chiselinfo::chiselinfo()
{
	m_filter = NULL;
	m_formatter = NULL;
}

void chiselinfo::init(sinsp* inspector, string filterstr, string formatterstr)
{
	if(filterstr != "")
	{
		m_filter = new sinsp_filter(inspector, filterstr);
	}

	if(formatterstr != "")
	{
		m_formatter = new sinsp_evt_formatter(inspector, formatterstr);
	}
	else
	{
		m_formatter = new sinsp_evt_formatter(inspector, DEFAULT_OUTPUT_STR);
	}
}

chiselinfo::~chiselinfo()
{
	if(m_filter)
	{
		delete m_filter;
	}

	if(m_formatter)
	{
		delete m_formatter;
	}
}

vector<string> m_chisel_paths;

///////////////////////////////////////////////////////////////////////////////
// chisel implementation
///////////////////////////////////////////////////////////////////////////////
chisel::chisel(sinsp* inspector, string filename)
{
	m_inspector = inspector;
	load(filename);
	m_root = NULL;
}

chisel::~chisel()
{
	for(vector<chiselinfo*>::iterator it = m_subchisels.begin(); it != m_subchisels.end(); ++it)
	{
		delete *it;
	}

	if(m_root != NULL)
	{
		delete m_root;
	}
}

void chisel::get_chisel_list(vector<chisel_desc>* chisel_descs)
{
	uint32_t j;

	for(j = 0; j < sizeof(chisel_dirs) / sizeof(chisel_dirs[0]); j++)
	{
		if(string(chisel_dirs[j].m_dir) == "")
		{
			continue;
		}

		tinydir_dir dir;
		tinydir_open(&dir, chisel_dirs[j].m_dir);

		while(dir.has_next)
		{
			tinydir_file file;
			tinydir_readfile(&dir, &file);

			string fname(file.name);
			string fpath(file.path);

			if(fname.find(".sc") != string::npos)
			{
				try
				{
					chisel ch(NULL, fpath);

					chisel_desc cd;
					cd.m_name = fname.substr(0, fname.rfind('.'));
					cd.m_description = ch.m_description;

					const Json::Value args = (*ch.m_root)["info"]["arguments"];
					for(uint32_t k = 0; k < args.size(); k++)
					{
						cd.m_args.push_back(chiselarg_desc(args[k]["name"].asString(), 
							args[k]["type"].asString(), 
							args[k]["description"].asString()));
					}

					chisel_descs->push_back(cd);
				}
				catch(...)
				{
					//
					// If there was an error opening the chisel, skip to the next one
					//
					goto next_file;
				}
			}

next_file:
			tinydir_next(&dir);
		}

		tinydir_close(&dir);
	}
}

//
// If the function succeeds, is is initialized to point to the file.
// Otherwise, the return value is "false".
//
bool chisel::openfile(string filename, OUT ifstream* is)
{
	uint32_t j;

	for(j = 0; j < sizeof(chisel_dirs) / sizeof(chisel_dirs[0]); j++)
	{
		if(chisel_dirs[j].m_need_to_resolve)
		{
#ifndef _WIN32
			char resolved_path[PATH_MAX];

			if(realpath((string(chisel_dirs[j].m_dir) + filename).c_str(), resolved_path) != NULL)
			{
				string rfilename(resolved_path);

				is->open(rfilename);
				if(is->is_open())
				{
					return true;
				}
			}
#endif
		}
		else
		{
			is->open(string(chisel_dirs[j].m_dir) + filename);
			if(is->is_open())
			{
				return true;
			}
		}
	}

	return false;
}

void chisel::load(string cmdstr)
{
	m_filename = cmdstr;
	trim(cmdstr);

	ifstream is;

	//
	// Try to open the file as is
	//
	if(!openfile(m_filename, &is))
	{
		//
		// Try to add the .cs extension
		//
		if(!openfile(m_filename + ".cs", &is))
		{
			throw sinsp_exception("can't open file " + m_filename);
		}
	}

	//
	// Bring the file into a string
	//
	string docstr((istreambuf_iterator<char>(is)),
		istreambuf_iterator<char>());

	//
	// Parse the json
	//
	if(m_root != NULL)
	{
		delete m_root;
	}

	m_root = new Json::Value();

	Json::Reader reader;
	bool parsingSuccessful = reader.parse(docstr, (*m_root));
	if(!parsingSuccessful)
	{
		throw sinsp_exception("Failed to parse chisel " + m_filename + ":" + 
			reader.getFormattedErrorMessages());
	}

	//
	// Extract the info
	//
	m_description = (*m_root)["info"]["description"].asString();
		
	is.close();
}

uint32_t chisel::get_n_args()
{
	return (*m_root)["info"]["arguments"].size();
}

void chisel::set_args(vector<string>* argvals)
{
	uint32_t j, k;
	const Json::Value args = (*m_root)["info"]["arguments"];

	m_argvals = *argvals;

	//
	// Validate the arguments
	//
	if(m_argvals.size() != args.size())
	{
		throw sinsp_exception("wrong number of parameters for chisel " + m_filename);
	}

	//
	// Apply the arguments
	//
	const Json::Value clst = (*m_root)["chisels"];
		
	for(j = 0; j < clst.size(); j++)
	{
		string filter = clst[j]["filter"].asString();
		for(k = 0; k < args.size(); k++)
		{
			replace_in_place(filter, 
				string("$") + args[k]["name"].asString(), 
				string(m_argvals[k]));
		}

		string formatter = clst[j]["format"].asString();
		for(k = 0; k < args.size(); k++)
		{
			replace_in_place(formatter, 
				string("$") + args[k]["name"].asString(), 
				string(m_argvals[k]));
		}

		chiselinfo* ci = new chiselinfo();
		ci->init(m_inspector, filter, formatter);
		m_subchisels.push_back(ci);
	}
}

void chisel::run(sinsp_evt* evt)
{
	uint32_t j;
	string line;

	for(j = 0; j < m_subchisels.size(); j++)
	{
		//
		// Output the line
		//
		if(m_subchisels[j]->m_filter != NULL)
		{
			if(!m_subchisels[j]->m_filter->run(evt))
			{
				continue;
			}
		}

		if(m_subchisels[j]->m_formatter->tostring(evt, &line))
		{
			cout << line << endl;
		}
	}
}

#endif // HAS_CHISELS
