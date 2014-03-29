#pragma once

class sinsp_filter_check;

/** @defgroup event Event manipulation
 *  @{
 */

/*!
  \brief Event to string converter class.
  This class can be used to format an event into a string, based on an arbitrary
  format.
*/
class SINSP_PUBLIC sinsp_evt_formatter
{
public:
	/*!
	  \brief Constructs a formatter.

	  \param inspector Pointer to the inspector instance that will generate the 
	   events to be formatter.
	  \param fmt The printf-like format to use. The accepted format is the same
	   as the one of the sysdig '-p' command line flag, so refer to the sysdig 
	   manual for details. 
	*/
	sinsp_evt_formatter(sinsp* inspector, const string& fmt);

	~sinsp_evt_formatter();

	/*!
	  \brief Fills res with the string rendering of the event.

	  \param evt Pointer to the event to be converted into string.
	  \param res Pointer to the string that will be filled with the result. 

	  \return true if the string should be shown (based on the initial *), 
	   false otherwise.
	*/
	bool tostring(sinsp_evt* evt, OUT string* res);

private:
	void set_format(const string& fmt);
	vector<sinsp_filter_check*> m_tokens;
	sinsp* m_inspector;
	bool m_require_all_values;
	vector<sinsp_filter_check*> m_chks_to_free;
};

/*@}*/
