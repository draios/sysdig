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

#undef HAS_LUA_CHISELS

#ifdef HAS_LUA_CHISELS
extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}
#endif

extern vector<chiseldir_info>* g_chisel_dirs;

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
	m_root = NULL;
	load(filename);
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

#ifdef HAS_LUA_CHISELS
void parse_lua_chisel_arg(lua_State *ls, OUT chisel_desc* cd)
{
	lua_pushnil(ls);
	string name;
	string type;
	string desc;

	while(lua_next(ls, -2) != 0)
	{
		if(lua_isstring(ls, -1))
		{
			if(string(lua_tostring(ls, -2)) == "name")
			{
				name = lua_tostring(ls, -1);
			}
			else if(string(lua_tostring(ls, -2)) == "argtype")
			{
				type = lua_tostring(ls, -1);
			}
			else if(string(lua_tostring(ls, -2)) == "description")
			{
				desc = lua_tostring(ls, -1);
			}
		}
		else
		{
			throw sinsp_exception(string(lua_tostring(ls, -2)) + " is not a string");
		}

		lua_pop(ls, 1);
	}

	cd->m_args.push_back(chiselarg_desc(name, type, desc));
}

void parse_lua_chisel_args(lua_State *ls, OUT chisel_desc* cd)
{
	lua_pushnil(ls);

	while(lua_next(ls, -2) != 0)
	{
		if(lua_isstring(ls, -1))
		{
			printf("%s = %s\n", lua_tostring(ls, -2), lua_tostring(ls, -1));
			cd->m_description = lua_tostring(ls, -1);
		}
		else if(lua_istable(ls, -1))
		{
			parse_lua_chisel_arg(ls, cd);
		}
		else
		{
			throw sinsp_exception(string(lua_tostring(ls, -2)) + " is not a string");
		}

		lua_pop(ls, 1);
	}
}
#endif

void chisel::get_chisel_list(vector<chisel_desc>* chisel_descs)
{
	uint32_t j;

	for(j = 0; j < g_chisel_dirs->size(); j++)
	{
		if(string(g_chisel_dirs->at(j).m_dir) == "")
		{
			continue;
		}

		tinydir_dir dir;
		tinydir_open(&dir, g_chisel_dirs->at(j).m_dir);

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

#ifdef HAS_LUA_CHISELS
			if(fname.find(".lua") != string::npos)
			{
				chisel_desc cd;
				cd.m_name = fname.substr(0, fname.rfind('.'));

				lua_State* ls = lua_open();
 
				luaL_openlibs(ls);
 
				if(luaL_loadfile(ls, fpath.c_str()) || lua_pcall(ls, 0, 0, 0)) 
				{
					fprintf(stderr, "error: %s", lua_tostring(ls, -1));
					goto next_lua_file;
				}

				//
				// Extract the description
				//
				lua_getglobal(ls, "description");
				if(!lua_isstring(ls, -1)) 
				{
					goto next_lua_file;
				}				

				cd.m_description = lua_tostring(ls, -1);

				//
				// Extract the args
				//
				lua_getglobal(ls, "args");

				try
				{
					parse_lua_chisel_args(ls, &cd);
				}
				catch(...)
				{
					goto next_lua_file;
				}

next_lua_file:
				lua_close(ls);
			}
#endif

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

	for(j = 0; j < g_chisel_dirs->size(); j++)
	{
		if(g_chisel_dirs->at(j).m_need_to_resolve)
		{
#ifndef _WIN32
			char resolved_path[PATH_MAX];

			if(realpath((string(g_chisel_dirs->at(j).m_dir) + filename).c_str(), resolved_path) != NULL)
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
			is->open(string(g_chisel_dirs->at(j).m_dir) + filename);
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
		// Try to add the .sc extension
		//
		if(!openfile(m_filename + ".sc", &is))
		{
			if(!openfile(m_filename + ".lua", &is))
			{
				throw sinsp_exception("can't open file " + m_filename);
			}
		}
	}

	//
	// Bring the file into a string
	//
	string docstr((istreambuf_iterator<char>(is)),
		istreambuf_iterator<char>());

	//
	// Try to parse as json
	//
	if(m_root != NULL)
	{
		delete m_root;
	}

	m_root = new Json::Value();

	Json::Reader reader;
	bool parsingSuccessful = reader.parse(docstr, (*m_root));
	if(parsingSuccessful)
	{
		//
		// Extract the info
		//
		m_description = (*m_root)["info"]["description"].asString();
	}
	else
	{
#ifdef HAS_LUA_CHISELS
//		string str(static_cast<stringstream const&>(stringstream() << is.rdbuf()).str());
std::string s( (std::istreambuf_iterator<char>( is )),
               (std::istreambuf_iterator<char>()) );

		std::istreambuf_iterator<char> eos;
		std::string scriptstr(std::istreambuf_iterator<char>(is), eos);

		lua_State* ls = lua_open();
 
		luaL_openlibs(ls);

		if(luaL_loadstring(ls, scriptstr.c_str()) || lua_pcall(ls, 0, 0, 0)) 
		{
			throw sinsp_exception("Failed to load chisel " + 
				m_filename + ":" + lua_tostring(ls, -1));
		}

		lua_close(ls);
#endif
	}

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

/*
				if(luaL_loadfile(ls, fpath.c_str()) || lua_pcall(ls, 0, 0, 0)) 
				{
					printf("error: %s", lua_tostring(ls, -1));
					goto next_file;
				}

				lua_getglobal(ls, "get_info");
				if(!lua_isfunction(ls, -1))
				{
					lua_pop(ls, 1);
					goto next_file;
				}

				//
				// call get_info
				//
				if(lua_pcall(ls, 2, 1, 0) != 0) 
				{
					printf("error running function `f': %s\n", lua_tostring(ls, -1));
					goto next_file;
				}

				if(!lua_isstring(ls, -1)) 
				{
					goto next_file;
				}

				const char* s = lua_tostring(ls, -1);
				lua_pop(ls, 1);

				lua_close(ls);
*/