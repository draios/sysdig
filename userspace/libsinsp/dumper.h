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

	~sinsp_dumper();

	/*!
	  \brief Opens the dump file.

	  \param filename The name of the target file.

	  \note There's no close() because the file is closed when the dumper is
	   destroyed.
	*/
	void open(const string& filename);

	/*!
	  \brief Return the current size of a tracefile.

	  \return The current size of the dump file. 
	*/
	uint64_t written_bytes();

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
