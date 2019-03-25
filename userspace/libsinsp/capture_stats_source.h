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
 */
class SINSP_PUBLIC capture_stats_source
{
public:
	virtual ~capture_stats_source() = default;

	virtual void get_capture_stats(scap_stats* stats) = 0;
};
