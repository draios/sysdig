#include "sinsp.h"
#include "sinsp_int.h"
#include "cyclewriter.h"

cycle_writer::cycle_writer() :
	m_base_file_name(""),
	m_rollover_mb(0),
	m_duration_seconds(0),
	m_file_limit(0),
	m_do_cycle(false),
	m_byte_count(0),
	m_last_time(0),
	m_file_count_total(0),
	m_file_index(0),
	m_first_consider(false)
{
	//
	// null terminate the first
	// character of the limit format
	// to say that we want things to
	// be created when we consider() the 
	// next file.
	//
	m_limit_format[0] = 0;
}

bool cycle_writer::setup(string base_file_name, int rollover_mb, int duration_seconds, int file_limit, bool do_cycle) 
{
	if(m_first_consider) 
	{
		return false;
	}
	m_base_file_name = base_file_name;
	m_rollover_mb = rollover_mb;
	m_duration_seconds = duration_seconds;
	m_file_limit = file_limit;
	m_do_cycle = do_cycle;

	//
	// Seed the filename with an initial
	// value.
	//
	consider(0);
	return true;
}

// 
// consider a certain number of bytes given the parameters
// passed in through setup.  Consider will recommend one 
// of the following:
//
//  * SAMEFILE - use the same file
//  * NEWFILE - use a new file (inquiry with get_current_file_name())
//  * DOQUI - end the capture.
//
cycle_writer::conclusion cycle_writer::consider(long byte_count) 
{
	m_byte_count += byte_count;

	if(m_duration_seconds > 0) 
	{
		//
		// If this is our first consideration, 
		// we set the timer up.
		// 
		if(m_last_time == 0) 
		{
			m_last_time = time(0);
		}

		//
		// If the current time is more than the last,
		// this is beyond our permissable limit
		//
		if(time(0) - m_last_time >= m_duration_seconds) 
		{
			// Reset the last time to now.
			m_last_time = time(0);

			// Reset our file numbering back to 0.
			//
			// NOTE: tcpdump doesn't do this necessarily and
			//   it's pretty confusing.
			m_file_index = 0;

			// Also bring back our byte_count since this
			// will be a new file to consider.
			m_byte_count = byte_count;

			// Set the last reason
			m_last_reason = "Maximum Time Reached";

			// Create a new file name and recommend it.
			return next_file();
		}
	}

	if(m_rollover_mb > 0) 
	{
		//
		// If we've rolled over the amount of bytes we
		// are supposed to write to a specific file then
		//
		if(m_byte_count > m_rollover_mb * 1000 * 1000) 
		{
			// Reset the counter back to the amount
			// we considered to write this time
			m_byte_count = byte_count;

			// Set the last reason
			m_last_reason = "Maximum File Size Reached";

			//
			// Increment our naming convention and 
			// return our advice.
			//
			return next_file();
		}
	}

	//
	// This is for any routine which restricts 
	// execution after an initial consider()
	//
	if(m_first_consider == false) 
	{
		m_first_consider = true;

		// We need to generate an initial file name
		// but still continue our logic.
		next_file();
	}

	// 
	// If we got here, this means that none 
	// of our limits were hit, so we 
	// recommend using the same file.
	//
	return SAMEFILE;
}

// 
// get_current_file_name - returns the name of the
// currently recommended file given the input parameters
//
string cycle_writer::get_current_file_name() 
{
	return m_last_file_name;
}

//
// next_file doesn't return the file pointer
// instead it returns advice on whether a new
// file should be used or not.
//
// If it advices a new file, then the new file
// name advised can be found in the
// get_current_file_name() routine.
//
cycle_writer::conclusion cycle_writer::next_file() 
{
	//
	// If we were told to only write a limited number
	// of files
	//
	if (m_file_limit > 0) 
	{
		//
		// If we are not cycling and the total number
		// of files recommended exceeds the maximum
		// number that we've been told to consider
		//
		if(!m_do_cycle && m_file_count_total >= m_file_limit) 
		{
			//
			// We've reached our limit and have 
			// been instructed not to cycle in a ring, 
			// so we recommend a DOQUIT signaling the 
			// end of the capture.
			//
			m_last_reason = "Maximum Number of Capture Files Written";

			return DOQUIT;
		}

		//
		// Otherwise, we see if our current index exceeds
		// our limit
		// 
		if(m_file_index >= m_file_limit) 
		{
			//
			// If so, we reset the index back to zero. The 
			// file_index will by definition always be equal
			// to or less then the file_count_total so we don't
			// need to check for the cycle here because it will
			// be caught above and return out of the function.
			// 
			m_file_index = 0;
		}
	}
	
	//
	// If we've made it here then we need to
	// do a new file name.
	//
	// The consider() block will move the
	// m_last_time forward if needed so we
	// can trust that the value we have at
	// this point is valid.
	//
	// Our file name is base + number
	// when applicable.
	//	
	if(m_duration_seconds > 0) 
	{
		//
		// This means that we need to run strftime
		// over the base name.	We'll just allocate
		// a good static 400 bytes here for the file
		// name ... 260 is usually considered max path,
		// the edge cases where it isn't is really 
		// outside the scope of this comment block 
		// ... really.
		// 
		const size_t our_size = 400;
		size_t their_size;
		char file_name[our_size];
		const struct tm *our_time = localtime(&m_last_time);

		their_size = strftime(file_name, our_size, m_base_file_name.c_str(), our_time);

		if(their_size == 0) 
		{
			// TODO: we failed ...
		}

		// We now have our "base" filename
		m_last_file_name = file_name;
	} 
	else 
	{
		//
		// This means we aren't using the duration 
		// flag so we don't have to run the stftime
		// function ... our job is really easy!
		// 
		m_last_file_name = m_base_file_name; 
	}

	//
	// If we've specified to limit the number of 
	// bytes per file and we have made it here,
	// that means that we should append the 
	// current value of m_file_index (which was dealt
	// with above) on to the end of m_last_file_name
	// which we created from above.
	//
	if(m_file_limit > 0) 
	{
		//
		// If the first character value is null (explicitly set 
		// above in the constructor), this means we haven't created 
		// our format for the file numbering yet, so we do it now.
		//
		if(m_limit_format[0] == 0) 
		{
			// The maximum numbr of decimal digits we need.
			int digit_count = 0;

			// A temporary copy of the file limit for
			// our exploitation and fun.
			int our_file_limit = m_file_limit;

			//
			// In order to determine how many digits we 
			// need to express up to our file_limit 
			//
			// we just continuually divide by 10 until 
			// we get zero.
			//
			// It's really not bad.
			//
			while(our_file_limit > 0) 
			{
				digit_count++;
				our_file_limit /= 10;
			}

			//
			// Now we can construct our format which will
			// actually be put inside another snprintf() later on
			//
			snprintf(
				// The format we are trying to derive
				m_limit_format,
				sizeof(m_limit_format),

				//
				// Read the string below like this:
				//
				// %% 0(%d) d
				//     ^^^^
				//     '- This is the only part that
				//        this snprintf cares about.
				//
				// A value of "5" will yield the following:
				//
				//    __
				// %%0%dd
				//    |/
				// __ v
				// %%05d
				// |/
				// v
				// %05d
				//
				// Which iw what we want.
				//
				"%%0%dd",

				digit_count
			);
		}	

		//
		// Now that we have our format string, we can take
		// our base file name and append the current number 
		// to it. We need to allocate a new char for that
		// first. This is a number, we'll set aside 22 bytes
		// for it just to prepare for the 45th century AD
		// when that kind of storage comes free with every
		// cereal box.
		//
		char index[22];

		snprintf(index, sizeof(index), m_limit_format, m_file_index);

		// Tack the index string value on to our base.
		m_last_file_name += index;
	}

	// Increment the total number of files.
	m_file_count_total++;

	// Increment the current index.
	m_file_index++;

	// Return that we've recommended a new file.
	return NEWFILE;
}
