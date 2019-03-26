/**
 * @file
 *
 * Interface to capture_stats_source.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "sinsp_public.h"

class scap_stats;

/**
 * Interface to an object that can provide capture statistics.
 *
 * Note that this intention here is to apply the Interface Segregation
 * Principle (ISP) to class sinsp.  Some clients of sinsp need only the
 * get_capture_stats() API, and this interface exposes only that API.  Do
 * not add additional APIs here.  If some client of sinsp needs a different
 * set of APIs, introduce a new interface.
 */
class SINSP_PUBLIC capture_stats_source
{
public:
	virtual ~capture_stats_source() = default;

	/**
	 * Fill the given structure with statistics about the currently
	 * open capture.
	 *
	 * @note This may not work for a file-based capture source.
	 *
	 * @param[out] stats The capture statistics
	 */
	virtual void get_capture_stats(scap_stats* stats) = 0;
};
