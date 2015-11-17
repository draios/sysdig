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

////////////////////////////////////////////////////////////////////////////
// Private definitions for the scap library
////////////////////////////////////////////////////////////////////////////

#pragma once

#include "settings.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <assert.h>
#ifdef USE_ZLIB
#include <zlib.h>
#else
#define	gzFile FILE*
#define gzflush(X, Y) fflush(X)
#define gzopen fopen
#define	gzdopen(fd, mode) stdout
#define gzclose fclose
#define gzoffset ftell
#define gzwrite(F, B, S) fwrite(B, 1, S, F)
#define gzread(F, B, S) fread(B, 1, S, F)
#define gzseek fseek
#endif
#define GZ(X) ((gzFile) X)
#define VD(X) ((void *) X)

// Write the given fd info to disk
int32_t scap_fd_write_to_disk(scap_t* handle, scap_fdinfo* fdi, gzFile f);
// Populate the given fd by reading the info from disk
uint32_t scap_fd_read_from_disk(scap_t* handle, OUT scap_fdinfo* fdi, OUT size_t* nbytes, gzFile f);
// Parse the headers of a trace file and load the tables
int32_t scap_read_init(scap_t* handle, gzFile f);

#define CHECK_READ_SIZE(read_size, expected_size) if(read_size != expected_size) \
	{\
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "expecting %d bytes, read %d at %s, line %d. Is the file truncated?",\
			(int)expected_size,\
			(int)read_size,\
			__FILE__,\
			__LINE__);\
		return SCAP_FAILURE;\
	}

#ifdef __cplusplus
}
#endif