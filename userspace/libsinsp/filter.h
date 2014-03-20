/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#ifdef HAS_FILTERING

class sinsp_filter_expression;

enum boolop
{
	BO_NONE = 0,
	BO_NOT = 1,
	BO_OR = 2,
	BO_AND = 4,
	BO_ORNOT = 3,
	BO_ANDNOT = 5,
};

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

/*!
  \brief This is the class that compiles and runs sysdig-type filters.
*/
class SINSP_PUBLIC sinsp_filter
{
public:
	/*!
	  \brief Constructs the filter.

	  \param inspector Pointer to the inspector instance that will generate the 
	   events to be filtered.
	  \param fmt The printf-like format to use. The accepted format is the same
	   as the one of the sysdig '-p' command line flag, so refer to the sysdig 
	   manual for details.

	 \note Throws a sinsp_exception if the filter syntax is not valid.
	*/
	sinsp_filter(sinsp* inspector, string fltstr);

	~sinsp_filter();

	/*!
	  \brief Applies the filter to the given event.

	  \param evt Pointer that needs to be filtered.
	  \return true if the event is accepted by the filter, false if it's rejected. 
	*/
	bool run(sinsp_evt *evt);

private:
	enum state
	{
		ST_EXPRESSION_DONE,
		ST_NEED_EXPRESSION,
	};

	char next();
	bool compare_no_consume(string str);

	string next_operand(bool expecting_first_operand);
	ppm_cmp_operator next_comparison_operator();
	void parse_check(sinsp_filter_expression* parent_expr, boolop op);
	void push_expression(boolop op);
	void pop_expression();

	void compile(string fltstr);

	static bool isblank(char c);
	static bool is_special_char(char c);
	static bool is_bracket(char c);

	sinsp* m_inspector;

	string m_fltstr;
	int32_t m_scanpos;
	int32_t m_scansize;
	state m_state;
	sinsp_filter_expression* m_curexpr;
	boolop m_last_boolop;
	int32_t m_nest_level;

	sinsp_filter_expression* m_filter;

	friend class sinsp_evt_formatter;
};

/*@}*/

#endif // HAS_FILTERING
