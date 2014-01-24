#pragma once

class sinsp;
class sinsp_evt;

/** @defgroup misc Misc
 * Classes to perform miscellneous functionality
 *  @{
 */

/*!
  \brief A support class to dump events to file in scap format.
*/
class SINSP_PUBLIC sinsp_dumper
{
public:
	/*!
	  \brief Constructs the dumper.

	  \param inspector Pointer to the inspector object that will be the source
	   of the events to save.
	*/
	sinsp_dumper(sinsp* inspector);

	~sinsp_dumper();

	/*!
	  \brief Opens the dump file.

	  \param filename The name of the target file.

	  \note There's no close() because the file is closed when the dumper is
	   destroyed.
	*/
	void open(const string& filename);

	/*!
	  \brief Writes an event to the file.

	  \param evt Pointer to the event to dump.
	*/
	void dump(sinsp_evt* evt);

private:
	sinsp* m_inspector;
	scap_dumper_t* m_dumper;
};

/*@}*/
