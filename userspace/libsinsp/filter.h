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

///////////////////////////////////////////////////////////////////////////////
// The filter class
// This is the main class that compiles and runs filters
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_filter
{
public:
	sinsp_filter(sinsp* inspector, string fltstr);
	~sinsp_filter();
	bool run(sinsp_evt *evt);
	static bool isblank(char c);
	static bool is_special_char(char c);
	static bool is_bracket(char c);

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

#endif // HAS_FILTERING
