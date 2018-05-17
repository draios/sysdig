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

#pragma once

#include <set>
#include <vector>

#ifdef HAS_FILTERING

class sinsp_filter_expression;
class sinsp_filter_check;

/*
 * Operators to compare events
 */
enum cmpop {
	CO_NONE = 0,
	CO_EQ = 1,
	CO_NE = 2,
	CO_LT = 3,
	CO_LE = 4,
	CO_GT = 5,
	CO_GE = 6,
	CO_CONTAINS = 7,
	CO_IN = 8,
	CO_EXISTS = 9,
	CO_ICONTAINS = 10,
	CO_STARTSWITH = 11,
	CO_GLOB = 12,
	CO_PMATCH = 13
};

enum boolop
{
	BO_NONE = 0,
	BO_NOT = 1,
	BO_OR = 2,
	BO_AND = 4,

	// obtained by bitwise OR'ing with one of above ops
	BO_ORNOT = 3,
	BO_ANDNOT = 5,
};

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

/*!
  \brief This is the class that runs sysdig-type filters.
*/
class SINSP_PUBLIC sinsp_filter
{
public:
	/*!
	  \brief Constructs the filter.

	  \param inspector Pointer to the inspector instance that will generate the
	   events to be filtered.
	*/
	sinsp_filter(sinsp* inspector);

	~sinsp_filter();

	/*!
	  \brief Applies the filter to the given event.

	  \param evt Pointer that needs to be filtered.
	  \return true if the event is accepted by the filter, false if it's rejected.
	*/
	bool run(sinsp_evt *evt);
	void push_expression(boolop op);
	void pop_expression();
	void add_check(sinsp_filter_check* chk);

private:

	void parse_check(sinsp_filter_expression* parent_expr, boolop op);


	sinsp* m_inspector;

	sinsp_filter_expression* m_curexpr;
	sinsp_filter_expression* m_filter;

	friend class sinsp_evt_formatter;
};


/*!
  \brief This is the class that compiles sysdig-type filters.
*/
class SINSP_PUBLIC sinsp_filter_compiler
{
public:
	/*!
	  \brief Constructs the compiler.

	  \param inspector Pointer to the inspector instance that will generate the
	   events to be filtered.
	  \param fltstr the filter string to compile.
	  \param ttable_only for internal use only.

	 \note Throws a sinsp_exception if the filter syntax is not valid.
	*/
	sinsp_filter_compiler(sinsp* inspector/* xxx needed? */, const string& fltstr, bool ttable_only=false);

	~sinsp_filter_compiler();

	sinsp_filter* compile();

private:
	enum state
	{
		ST_EXPRESSION_DONE,
		ST_NEED_EXPRESSION,
	};

	sinsp_filter* compile_();

	char next();
	bool compare_no_consume(const string& str);

	vector<char> next_operand(bool expecting_first_operand, bool in_clause);
	cmpop next_comparison_operator();
	void parse_check();

	static bool isblank(char c);
	static bool is_special_char(char c);
	static bool is_bracket(char c);

	sinsp* m_inspector;
	bool m_ttable_only;

	string m_fltstr;
	int32_t m_scanpos;
	int32_t m_scansize;
	state m_state;
	boolop m_last_boolop;
	int32_t m_nest_level;

	sinsp_filter* m_filter;

	friend class sinsp_evt_formatter;
};

/*!
  \brief This class represents a filter optimized using event
  types. It actually consists of collections of sinsp_filter objects
  grouped by event type.
*/

class SINSP_PUBLIC sinsp_evttype_filter
{
public:
	sinsp_evttype_filter();
	virtual ~sinsp_evttype_filter();

	void add(std::string &name,
		 std::set<uint32_t> &evttypes,
		 std::set<uint32_t> &syscalls,
		 std::set<string> &tags,
		 sinsp_filter* filter);

	// rulesets are arbitrary numbers and should be managed by the caller.
        // Note that rulesets are used to index into a std::vector so
        // specifying unnecessarily large rulesets will result in
        // unnecessarily large vectors.

	// Find those rules matching the provided pattern and set
	// their enabled status to enabled.
	void enable(const std::string &pattern, bool enabled, uint16_t ruleset = 0);

	// Find those rules that have a tag in the set of tags and set
	// their enabled status to enabled. Note that the enabled
	// status is on the rules, and not the tags--if a rule R has
	// tags (a, b), and you call enable_tags([a], true) and then
	// enable_tags([b], false), R will be disabled despite the
	// fact it has tag a and was enabled by the first call to
	// enable_tags.
	void enable_tags(const std::set<string> &tags, bool enabled, uint16_t ruleset = 0);

	// Match all filters against the provided event.
	bool run(sinsp_evt *evt, uint16_t ruleset = 0);

	// Populate the provided vector, indexed by event type, of the
	// event types associated with the given ruleset id. For
	// example, evttypes[10] = true would mean that this ruleset
	// relates to event type 10.
	void evttypes_for_ruleset(std::vector<bool> &evttypes, uint16_t ruleset);

	// Populate the provided vector, indexed by syscall code, of the
	// syscall codes associated with the given ruleset id. For
	// example, syscalls[10] = true would mean that this ruleset
	// relates to syscall code 10.
	void syscalls_for_ruleset(std::vector<bool> &syscalls, uint16_t ruleset);

private:

	struct filter_wrapper {
		sinsp_filter *filter;

		// Indexes from event type to enabled/disabled.
		std::vector<bool> evttypes;

		// Indexes from syscall code to enabled/disabled.
		std::vector<bool> syscalls;
	};

	// A group of filters all having the same ruleset
	class ruleset_filters {
	public:
		ruleset_filters();

		virtual ~ruleset_filters();

		void add_filter(filter_wrapper *wrap);

		bool run(sinsp_evt *evt);

		void evttypes_for_ruleset(std::vector<bool> &evttypes);

		void syscalls_for_ruleset(std::vector<bool> &syscalls);

	private:
		// Maps from event type to filter. There can be multiple
		// filters per event type.
		std::list<filter_wrapper *> *m_filter_by_evttype[PPM_EVENT_MAX];

		// Maps from syscall number to filter. There can be multiple
		// filters per syscall number
		std::list<filter_wrapper *> *m_filter_by_syscall[PPM_SC_MAX];
	};

	std::vector<ruleset_filters *> m_rulesets;

	// Maps from tag to list of filters having that tag.
	std::map<std::string, std::list<filter_wrapper *>> m_filter_by_tag;

	// This holds all the filters passed to add(), so they can
	// be cleaned up.
	map<std::string,filter_wrapper *> m_filters;
};

/*@}*/

#endif // HAS_FILTERING
