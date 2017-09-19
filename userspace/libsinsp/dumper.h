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

class sinsp;
class sinsp_evt;

/** @defgroup dump Dumping events to disk
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

	/*!
	  \brief Constructs a dumper that saves to memory instead of disk.
	  Takes the address and the size of a preallocated memory buffer
	  where the data will go.
	*/
	sinsp_dumper(sinsp* inspector,
		uint8_t* target_memory_buffer,
		uint64_t target_memory_buffer_size);

	~sinsp_dumper();

	/*!
	  \brief Opens the dump file.

	  \param filename The name of the target file.

	  \param compress true to save the tracefile in a compressed format.

	  \param threads_from_sinsp If, true the thread and FD tables in the file
	   will be created from the current sinsp's tables instead of reusing the scap
	   ones.

	  \note There's no close() because the file is closed when the dumper is
	   destroyed.
	*/
	void open(const string& filename,
		bool compress,
		bool threads_from_sinsp=false);

	void fdopen(int fd,
		    bool compress,
		    bool threads_from_sinsp=false);

	/*!
	  \brief Closes the dump file.
	*/
	void close();

	/*!
	  \brief Return whether or not the underling scap file has been
	         opened.
	*/
	bool is_open();

	/*!
	  \brief Return the number of events dumped so far.
	*/
	bool written_events();

	/*!
	  \brief Return the current size of a tracefile.

	  \return The current size of the dump file.
	*/
	uint64_t written_bytes();

	/*!
	  \brief Return the starting position for the next write into
          	  the file. (Under the covers, this uses gztell while
        	  written_bytes uses gzoffset, which represent different values).

	  \return The starting position for the next write.
	*/
	uint64_t next_write_position();

	/*!
	  \brief Flush all pending output into the file.
	*/
	void flush();

	/*!
	  \brief Writes an event to the file.

	  \param evt Pointer to the event to dump.
	*/
	void dump(sinsp_evt* evt);

	inline uint8_t* get_memory_dump_cur_buf()
	{
		return scap_get_memorydumper_curpos(m_dumper);
	}

	inline void set_inspector(sinsp *inspector)
	{
		m_inspector = inspector;
	}

private:
	sinsp* m_inspector;
	scap_dumper_t* m_dumper;
	uint8_t* m_target_memory_buffer;
	uint64_t m_target_memory_buffer_size;
	uint64_t m_nevts;
};

/*@}*/
