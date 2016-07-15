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

#ifndef _WIN32
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include "scap.h"
#include "scap-int.h"
#include "scap_savefile.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// WRITE FUNCTIONS
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
#ifndef _WIN32
static inline uint32_t scap_normalize_block_len(uint32_t blocklen)
#else
static uint32_t scap_normalize_block_len(uint32_t blocklen)
#endif
{
	return ((blocklen + 3) >> 2) << 2;
}

static int32_t scap_write_padding(gzFile f, uint32_t blocklen)
{
	int32_t val = 0;
	uint32_t bytestowrite = scap_normalize_block_len(blocklen) - blocklen;

	if(gzwrite(f, &val, bytestowrite) == bytestowrite)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		return SCAP_FAILURE;
	}
}

static int32_t scap_write_proc_fds(scap_t *handle, struct scap_threadinfo *tinfo, gzFile f)
{
	block_header bh;
	uint32_t bt;
	uint32_t totlen = MEMBER_SIZE(scap_threadinfo, tid);  // This includes the tid
	struct scap_fdinfo *fdi;
	struct scap_fdinfo *tfdi;

	//
	// First pass of the table to calculate the length
	//
	HASH_ITER(hh, tinfo->fdlist, fdi, tfdi)
	{
		if(fdi->type != SCAP_FD_UNINITIALIZED)
		{
			totlen += scap_fd_info_len(fdi);
		}
	}

	//
	// Create the block
	//
	bh.block_type = FDL_BLOCK_TYPE;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	if(gzwrite(f, &bh, sizeof(bh)) != sizeof(bh))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd1)");
		return SCAP_FAILURE;
	}

	//
	// Write the tid
	//
	if(gzwrite(f, &tinfo->tid, sizeof(tinfo->tid)) != sizeof(tinfo->tid))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd2)");
		return SCAP_FAILURE;
	}

	//
	// Second pass pass of the table to dump it
	//
	HASH_ITER(hh, tinfo->fdlist, fdi, tfdi)
	{
		if(fdi->type != SCAP_FD_UNINITIALIZED)
		{
			if(scap_fd_write_to_disk(handle, fdi, f) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
		}
	}

	//
	// Add the padding
	//
	if(scap_write_padding(f, totlen) != SCAP_SUCCESS)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(gzwrite(f, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the fd list blocks
//
static int32_t scap_write_fdlist(scap_t *handle, gzFile f)
{
	struct scap_threadinfo *tinfo;
	struct scap_threadinfo *ttinfo;
	int32_t res;

	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		if(!tinfo->filtered_out)
		{
			res = scap_write_proc_fds(handle, tinfo, f);
			if(res != SCAP_SUCCESS)
			{
				return res;
			}
		}
	}

	return SCAP_SUCCESS;
}

//
// Write the process list block
//
static int32_t scap_write_proclist(scap_t *handle, gzFile f)
{
	block_header bh;
	uint32_t bt;
	uint32_t totlen = 0;
	struct scap_threadinfo *tinfo;
	struct scap_threadinfo *ttinfo;
	uint16_t commlen;
	uint16_t exelen;
	uint16_t argslen;
	uint16_t cwdlen;
	uint16_t rootlen;

	//
	// First pass pass of the table to calculate the length
	//
	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		if(!tinfo->filtered_out)
		{
			totlen += (uint32_t)
				(sizeof(uint64_t) +	// tid
				sizeof(uint64_t) +	// pid
				sizeof(uint64_t) +	// ptid
				sizeof(uint64_t) +	// sid
				2 + strnlen(tinfo->comm, SCAP_MAX_PATH_SIZE) +
				2 + strnlen(tinfo->exe, SCAP_MAX_PATH_SIZE) +
				2 + tinfo->args_len +
				2 + strnlen(tinfo->cwd, SCAP_MAX_PATH_SIZE) +
				sizeof(uint64_t) +	// fdlimit
				sizeof(uint32_t) +	// uid
				sizeof(uint32_t) +	// gid
				sizeof(uint32_t) +  // vmsize_kb
				sizeof(uint32_t) +  // vmrss_kb
				sizeof(uint32_t) +  // vmswap_kb
				sizeof(uint64_t) +  // pfmajor
				sizeof(uint64_t) +  // pfminor
				2 + tinfo->env_len +
				sizeof(int64_t) +  // vtid
				sizeof(int64_t) +  // vpid
				2 + tinfo->cgroups_len +
				sizeof(uint32_t) +
				2 + strnlen(tinfo->root, SCAP_MAX_PATH_SIZE));
		}
	}

	//
	// Create the block
	//
	bh.block_type = PL_BLOCK_TYPE_V6;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	if(gzwrite(f, &bh, sizeof(bh)) != sizeof(bh))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (1)");
		return SCAP_FAILURE;
	}

	//
	// Second pass pass of the table to dump it
	//
	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		if(tinfo->filtered_out)
		{
			continue;
		}

		commlen = (uint16_t)strnlen(tinfo->comm, SCAP_MAX_PATH_SIZE);
		exelen = (uint16_t)strnlen(tinfo->exe, SCAP_MAX_PATH_SIZE);
		argslen = tinfo->args_len;
		cwdlen = (uint16_t)strnlen(tinfo->cwd, SCAP_MAX_PATH_SIZE);
		rootlen = (uint16_t)strnlen(tinfo->root, SCAP_MAX_PATH_SIZE);

		if(gzwrite(f, &(tinfo->tid), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        gzwrite(f, &(tinfo->pid), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        gzwrite(f, &(tinfo->ptid), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        gzwrite(f, &(tinfo->sid), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        gzwrite(f, &commlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzwrite(f, tinfo->comm, commlen) != commlen ||
		        gzwrite(f, &exelen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzwrite(f, tinfo->exe, exelen) != exelen ||
		        gzwrite(f, &argslen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzwrite(f, tinfo->args, argslen) != argslen ||
		        gzwrite(f, &cwdlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzwrite(f, tinfo->cwd, cwdlen) != cwdlen ||
		        gzwrite(f, &(tinfo->fdlimit), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        gzwrite(f, &(tinfo->flags), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        gzwrite(f, &(tinfo->uid), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        gzwrite(f, &(tinfo->gid), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        gzwrite(f, &(tinfo->vmsize_kb), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        gzwrite(f, &(tinfo->vmrss_kb), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        gzwrite(f, &(tinfo->vmswap_kb), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        gzwrite(f, &(tinfo->pfmajor), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        gzwrite(f, &(tinfo->pfminor), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        gzwrite(f, &(tinfo->env_len), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzwrite(f, tinfo->env, tinfo->env_len) != tinfo->env_len ||
		        gzwrite(f, &(tinfo->vtid), sizeof(int64_t)) != sizeof(int64_t) ||
		        gzwrite(f, &(tinfo->vpid), sizeof(int64_t)) != sizeof(int64_t) ||
		        gzwrite(f, &(tinfo->cgroups_len), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzwrite(f, tinfo->cgroups, tinfo->cgroups_len) != tinfo->cgroups_len ||
		        gzwrite(f, &rootlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		        gzwrite(f, tinfo->root, rootlen) != rootlen)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (2)");
			return SCAP_FAILURE;
		}
	}

	//
	// Blocks need to be 4-byte padded
	//
	if(scap_write_padding(f, totlen) != SCAP_SUCCESS)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(gzwrite(f, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the machine info block
//
static int32_t scap_write_machine_info(scap_t *handle, gzFile f)
{
	block_header bh;
	uint32_t bt;

	//
	// Write the section header
	//
	bh.block_type = MI_BLOCK_TYPE;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + sizeof(scap_machine_info) + 4);

	bt = bh.block_total_length;

	if(gzwrite(f, &bh, sizeof(bh)) != sizeof(bh) ||
	        gzwrite(f, &handle->m_machine_info, sizeof(handle->m_machine_info)) != sizeof(handle->m_machine_info) ||
	        gzwrite(f, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (MI1)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the interface list block
//
static int32_t scap_write_iflist(scap_t *handle, gzFile f)
{
	block_header bh;
	uint32_t bt;
	uint32_t entrylen;
	uint32_t totlen = 0;
	uint32_t j;

	//
	// Get the interface list
	//
	if(handle->m_addrlist == NULL)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to trace file: interface list missing");
		return SCAP_FAILURE;
	}

	//
	// Create the block
	//
	bh.block_type = IL_BLOCK_TYPE;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + handle->m_addrlist->totlen + 4);

	if(gzwrite(f, &bh, sizeof(bh)) != sizeof(bh))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF1)");
		return SCAP_FAILURE;
	}

	//
	// Dump the ipv4 list
	//
	for(j = 0; j < handle->m_addrlist->n_v4_addrs; j++)
	{
		scap_ifinfo_ipv4 *entry = &(handle->m_addrlist->v4list[j]);

		entrylen = sizeof(scap_ifinfo_ipv4) + entry->ifnamelen - SCAP_MAX_PATH_SIZE;

		if(gzwrite(f, entry, entrylen) != entrylen)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF2)");
			return SCAP_FAILURE;
		}

		totlen += entrylen;
	}

	//
	// Dump the ipv6 list
	//
	for(j = 0; j < handle->m_addrlist->n_v6_addrs; j++)
	{
		scap_ifinfo_ipv6 *entry = &(handle->m_addrlist->v6list[j]);

		entrylen = sizeof(scap_ifinfo_ipv6) + entry->ifnamelen - SCAP_MAX_PATH_SIZE;

		if(gzwrite(f, entry, entrylen) != entrylen)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF2)");
			return SCAP_FAILURE;
		}

		totlen += entrylen;
	}

	//
	// Blocks need to be 4-byte padded
	//
	if(scap_write_padding(f, totlen) != SCAP_SUCCESS)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(gzwrite(f, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the user list block
//
static int32_t scap_write_userlist(scap_t *handle, gzFile f)
{
	block_header bh;
	uint32_t bt;
	uint32_t j;
	uint16_t namelen;
	uint16_t homedirlen;
	uint16_t shelllen;
	uint8_t type;
	uint32_t totlen = 0;

	//
	// Make sure we have a user list interface list
	//
	if(handle->m_userlist == NULL)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to trace file: user list missing");
		return SCAP_FAILURE;
	}

	//
	// Calculate the block length
	//
	for(j = 0; j < handle->m_userlist->nusers; j++)
	{
		scap_userinfo* info = &handle->m_userlist->users[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);
		homedirlen = (uint16_t)strnlen(info->homedir, SCAP_MAX_PATH_SIZE);
		shelllen = (uint16_t)strnlen(info->shell, SCAP_MAX_PATH_SIZE);

		totlen += sizeof(type) + sizeof(info->uid) + sizeof(info->gid) + sizeof(uint16_t) +
			namelen + sizeof(uint16_t) + homedirlen + sizeof(uint16_t) + shelllen;
	}

	for(j = 0; j < handle->m_userlist->ngroups; j++)
	{
		scap_groupinfo* info = &handle->m_userlist->groups[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);

		totlen += sizeof(type) + sizeof(info->gid) + sizeof(uint16_t) + namelen;
	}

	//
	// Create the block
	//
	bh.block_type = UL_BLOCK_TYPE;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	if(gzwrite(f, &bh, sizeof(bh)) != sizeof(bh))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF1)");
		return SCAP_FAILURE;
	}

	//
	// Dump the users
	//
	type = USERBLOCK_TYPE_USER;
	for(j = 0; j < handle->m_userlist->nusers; j++)
	{
		scap_userinfo* info = &handle->m_userlist->users[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);
		homedirlen = (uint16_t)strnlen(info->homedir, SCAP_MAX_PATH_SIZE);
		shelllen = (uint16_t)strnlen(info->shell, SCAP_MAX_PATH_SIZE);

		if(gzwrite(f, &(type), sizeof(type)) != sizeof(type) ||
			gzwrite(f, &(info->uid), sizeof(info->uid)) != sizeof(info->uid) ||
		    gzwrite(f, &(info->gid), sizeof(info->gid)) != sizeof(info->gid) ||
		    gzwrite(f, &namelen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		    gzwrite(f, info->name, namelen) != namelen ||
		    gzwrite(f, &homedirlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		    gzwrite(f, info->homedir, homedirlen) != homedirlen ||
		    gzwrite(f, &shelllen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		    gzwrite(f, info->shell, shelllen) != shelllen)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (U1)");
			return SCAP_FAILURE;
		}
	}

	//
	// Dump the groups
	//
	type = USERBLOCK_TYPE_GROUP;
	for(j = 0; j < handle->m_userlist->ngroups; j++)
	{
		scap_groupinfo* info = &handle->m_userlist->groups[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);

		if(gzwrite(f, &(type), sizeof(type)) != sizeof(type) ||
			gzwrite(f, &(info->gid), sizeof(info->gid)) != sizeof(info->gid) ||
		    gzwrite(f, &namelen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		    gzwrite(f, info->name, namelen) != namelen)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (U2)");
			return SCAP_FAILURE;
		}
	}

	//
	// Blocks need to be 4-byte padded
	//
	if(scap_write_padding(f, totlen) != SCAP_SUCCESS)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(gzwrite(f, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Create the dump file headers and add the tables
//
static scap_dumper_t *scap_setup_dump(scap_t *handle, gzFile f, const char *fname)
{
	block_header bh;
	section_header_block sh;
	uint32_t bt;

	//
	// Write the section header
	//
	bh.block_type = SHB_BLOCK_TYPE;
	bh.block_total_length = sizeof(block_header) + sizeof(section_header_block) + 4;

	sh.byte_order_magic = SHB_MAGIC;
	sh.major_version = CURRENT_MAJOR_VERSION;
	sh.minor_version = CURRENT_MINOR_VERSION;
	sh.section_length = 0xffffffffffffffffLL;

	bt = bh.block_total_length;

	if(gzwrite(f, &bh, sizeof(bh)) != sizeof(bh) ||
	        gzwrite(f, &sh, sizeof(sh)) != sizeof(sh) ||
	        gzwrite(f, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file %s  (5)", fname);
		return NULL;
	}

	//
	// If we're dumping in live mode, refresh the process tables list
	// so we don't lose information about processes created in the interval
	// between opening the handle and starting the dump
	//
#if defined(HAS_CAPTURE)
	if(handle->m_file == NULL && handle->refresh_proc_table_when_saving)
	{
		proc_entry_callback tcb = handle->m_proc_callback;
		handle->m_proc_callback = NULL;

		scap_proc_free_table(handle);
		char filename[SCAP_MAX_PATH_SIZE];
		snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
		if(scap_proc_scan_proc_dir(handle, filename, -1, -1, NULL, handle->m_lasterr, true) != SCAP_SUCCESS)
		{
			handle->m_proc_callback = tcb;
			return NULL;
		}

		handle->m_proc_callback = tcb;
	}
#endif

	//
	// Write the machine info
	//
	if(scap_write_machine_info(handle, f) != SCAP_SUCCESS)
	{
		return NULL;
	}

	//
	// Write the interface list
	//
	if(scap_write_iflist(handle, f) != SCAP_SUCCESS)
	{
		return NULL;
	}

	//
	// Write the user list
	//
	if(scap_write_userlist(handle, f) != SCAP_SUCCESS)
	{
		return NULL;
	}

	//
	// Write the process list
	//
	if(scap_write_proclist(handle, f) != SCAP_SUCCESS)
	{
		return NULL;
	}

	//
	// Write the fd lists
	//
	if(scap_write_fdlist(handle, f) != SCAP_SUCCESS)
	{
		return NULL;
	}

	//
	// If the user doesn't need the thread table, free it
	//
	if(handle->m_proc_callback != NULL)
	{
		scap_proc_free_table(handle);
	}

	//
	// Done, return the file
	//
	return (scap_dumper_t *)f;
}

//
// Open a "savefile" for writing.
//
scap_dumper_t *scap_dump_open(scap_t *handle, const char *fname, compression_mode compress)
{
	gzFile f = NULL;
	int fd = -1;
	const char* mode;

	switch(compress)
	{
	case SCAP_COMPRESSION_GZIP:
		mode = "wb";
		break;
	case SCAP_COMPRESSION_NONE:
		mode = "wbT";
		break;
	default:
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid compression mode");
		return NULL;
	}

	if(fname[0] == '-' && fname[1] == '\0')
	{
#ifndef	_WIN32
		fd = dup(STDOUT_FILENO);
#else
		fd = 1;
#endif
		if(fd != -1)
		{
			f = gzdopen(fd, mode);
			fname = "standard output";
		}
	}
	else
	{
		f = gzopen(fname, mode);
	}

	if(f == NULL)
	{
#ifndef	_WIN32
		if(fd != -1)
		{
			close(fd);
		}
#endif

		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open %s", fname);
		return NULL;
	}

	return scap_setup_dump(handle, f, fname);
}

//
// Close a "savefile" opened with scap_dump_open
//
void scap_dump_close(scap_dumper_t *d)
{
	gzclose((gzFile)d);
}

//
// Return the current size of a tracefile
//
int64_t scap_dump_get_offset(scap_dumper_t *d)
{
	return gzoffset((gzFile)d);
}

void scap_dump_flush(scap_dumper_t *d)
{
	gzflush((gzFile)d, Z_FULL_FLUSH);
}

//
// Tell me how many bytes we will have written if we did.
//
int32_t scap_number_of_bytes_to_write(scap_evt *e, uint16_t cpuid, int32_t *bytes)
{
	*bytes = scap_normalize_block_len(sizeof(block_header) + sizeof(cpuid) + e->len + 4);

	return SCAP_SUCCESS;
}

//
// Write an event to a dump file
//
int32_t scap_dump(scap_t *handle, scap_dumper_t *d, scap_evt *e, uint16_t cpuid, uint32_t flags)
{
	block_header bh;
	uint32_t bt;
	gzFile f = (gzFile)d;

	if(flags == 0)
	{
		//
		// Write the section header
		//
		bh.block_type = EV_BLOCK_TYPE;
		bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + sizeof(cpuid) + e->len + 4);
		bt = bh.block_total_length;

		if(gzwrite(f, &bh, sizeof(bh)) != sizeof(bh) ||
				gzwrite(f, &cpuid, sizeof(cpuid)) != sizeof(cpuid) ||
				gzwrite(f, e, e->len) != e->len ||
				scap_write_padding(f, sizeof(cpuid) + e->len) != SCAP_SUCCESS ||
				gzwrite(f, &bt, sizeof(bt)) != sizeof(bt))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (6)");
			return SCAP_FAILURE;
		}
	}
	else
	{
		//
		// Write the section header
		//
		bh.block_type = EVF_BLOCK_TYPE;
		bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + sizeof(cpuid) + sizeof(flags) + e->len + 4);
		bt = bh.block_total_length;

		if(gzwrite(f, &bh, sizeof(bh)) != sizeof(bh) ||
				gzwrite(f, &cpuid, sizeof(cpuid)) != sizeof(cpuid) ||
				gzwrite(f, &flags, sizeof(flags)) != sizeof(flags) ||
				gzwrite(f, e, e->len) != e->len ||
				scap_write_padding(f, sizeof(cpuid) + e->len) != SCAP_SUCCESS ||
				gzwrite(f, &bt, sizeof(bt)) != sizeof(bt))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (7)");
			return SCAP_FAILURE;
		}
	}

	//
	// Enable this to make sure that everything is saved to disk during the tests
	//
#if 0
	fflush(f);
#endif

	return SCAP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// READ FUNCTIONS
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

//
// Load the machine info block
//
static int32_t scap_read_machine_info(scap_t *handle, gzFile f, uint32_t block_length)
{
	//
	// Read the section header block
	//
	if(gzread(f, &handle->m_machine_info, sizeof(handle->m_machine_info)) !=
		sizeof(handle->m_machine_info))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Parse a process list block
//
static int32_t scap_read_proclist(scap_t *handle, gzFile f, uint32_t block_length, uint32_t block_type)
{
	size_t readsize;
	size_t totreadsize = 0;
	size_t padding_len;
	struct scap_threadinfo tinfo;
	uint16_t stlen;
	uint32_t padding;
	int32_t uth_status = SCAP_SUCCESS;
	struct scap_threadinfo *ntinfo;

	tinfo.fdlist = NULL;
	tinfo.flags = 0;
	tinfo.vmsize_kb = 0;
	tinfo.vmrss_kb = 0;
	tinfo.vmswap_kb = 0;
	tinfo.pfmajor = 0;
	tinfo.pfminor = 0;
	tinfo.env_len = 0;
	tinfo.vtid = -1;
	tinfo.vpid = -1;
	tinfo.cgroups_len = 0;
	tinfo.filtered_out = 0;
	tinfo.root[0] = 0;
	tinfo.sid = -1;

	while(((int32_t)block_length - (int32_t)totreadsize) >= 4)
	{
		//
		// tid
		//
		readsize = gzread(f, &(tinfo.tid), sizeof(uint64_t));
		CHECK_READ_SIZE(readsize, sizeof(uint64_t));

		totreadsize += readsize;

		//
		// pid
		//
		readsize = gzread(f, &(tinfo.pid), sizeof(uint64_t));
		CHECK_READ_SIZE(readsize, sizeof(uint64_t));

		totreadsize += readsize;

		//
		// ptid
		//
		readsize = gzread(f, &(tinfo.ptid), sizeof(uint64_t));
		CHECK_READ_SIZE(readsize, sizeof(uint64_t));

		totreadsize += readsize;

		switch(block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
			break;
		case PL_BLOCK_TYPE_V6:
			readsize = gzread(f, &(tinfo.sid), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));

			totreadsize += readsize;
			break;

		default:
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		//
		// comm
		//
		readsize = gzread(f, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE(readsize, sizeof(uint16_t));

		if(stlen > SCAP_MAX_PATH_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid commlen %d", stlen);
			return SCAP_FAILURE;
		}

		totreadsize += readsize;

		readsize = gzread(f, tinfo.comm, stlen);
		CHECK_READ_SIZE(readsize, stlen);

		// the string is not null-terminated on file
		tinfo.comm[stlen] = 0;

		totreadsize += readsize;

		//
		// exe
		//
		readsize = gzread(f, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE(readsize, sizeof(uint16_t));

		if(stlen > SCAP_MAX_PATH_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid exelen %d", stlen);
			return SCAP_FAILURE;
		}

		totreadsize += readsize;

		readsize = gzread(f, tinfo.exe, stlen);
		CHECK_READ_SIZE(readsize, stlen);

		// the string is not null-terminated on file
		tinfo.exe[stlen] = 0;

		totreadsize += readsize;

		//
		// args
		//
		readsize = gzread(f, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE(readsize, sizeof(uint16_t));

		if(stlen > SCAP_MAX_ARGS_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid argslen %d", stlen);
			return SCAP_FAILURE;
		}

		totreadsize += readsize;

		readsize = gzread(f, tinfo.args, stlen);
		CHECK_READ_SIZE(readsize, stlen);

		// the string is not null-terminated on file
		tinfo.args[stlen] = 0;
		tinfo.args_len = stlen;

		totreadsize += readsize;

		//
		// cwd
		//
		readsize = gzread(f, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE(readsize, sizeof(uint16_t));

		if(stlen > SCAP_MAX_PATH_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid cwdlen %d", stlen);
			return SCAP_FAILURE;
		}

		totreadsize += readsize;

		readsize = gzread(f, tinfo.cwd, stlen);
		CHECK_READ_SIZE(readsize, stlen);

		// the string is not null-terminated on file
		tinfo.cwd[stlen] = 0;

		totreadsize += readsize;

		//
		// fdlimit
		//
		readsize = gzread(f, &(tinfo.fdlimit), sizeof(uint64_t));
		CHECK_READ_SIZE(readsize, sizeof(uint64_t));

		totreadsize += readsize;

		//
		// flags
		//
		readsize = gzread(f, &(tinfo.flags), sizeof(uint32_t));
		CHECK_READ_SIZE(readsize, sizeof(uint32_t));

		totreadsize += readsize;

		//
		// uid
		//
		readsize = gzread(f, &(tinfo.uid), sizeof(uint32_t));
		CHECK_READ_SIZE(readsize, sizeof(uint32_t));

		totreadsize += readsize;

		//
		// gid
		//
		readsize = gzread(f, &(tinfo.gid), sizeof(uint32_t));
		CHECK_READ_SIZE(readsize, sizeof(uint32_t));

		totreadsize += readsize;

		switch(block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
			break;
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
			//
			// vmsize_kb
			//
			readsize = gzread(f, &(tinfo.vmsize_kb), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			totreadsize += readsize;

			//
			// vmrss_kb
			//
			readsize = gzread(f, &(tinfo.vmrss_kb), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			totreadsize += readsize;

			//
			// vmswap_kb
			//
			readsize = gzread(f, &(tinfo.vmswap_kb), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			totreadsize += readsize;

			//
			// pfmajor
			//
			readsize = gzread(f, &(tinfo.pfmajor), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));

			totreadsize += readsize;

			//
			// pfminor
			//
			readsize = gzread(f, &(tinfo.pfminor), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));

			totreadsize += readsize;

			if(block_type == PL_BLOCK_TYPE_V3 ||
				block_type == PL_BLOCK_TYPE_V3_INT ||
				block_type == PL_BLOCK_TYPE_V4 ||
				block_type == PL_BLOCK_TYPE_V5 ||
				block_type == PL_BLOCK_TYPE_V6)
			{
				//
				// env
				//
				readsize = gzread(f, &(stlen), sizeof(uint16_t));
				CHECK_READ_SIZE(readsize, sizeof(uint16_t));

				if(stlen > SCAP_MAX_ENV_SIZE)
				{
					snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid envlen %d", stlen);
					return SCAP_FAILURE;
				}

				totreadsize += readsize;

				readsize = gzread(f, tinfo.env, stlen);
				CHECK_READ_SIZE(readsize, stlen);

				// the string is not null-terminated on file
				tinfo.env[stlen] = 0;
				tinfo.env_len = stlen;

				totreadsize += readsize;
			}

			if(block_type == PL_BLOCK_TYPE_V4 ||
			   block_type == PL_BLOCK_TYPE_V5 ||
			   block_type == PL_BLOCK_TYPE_V6)
			{
				//
				// vtid
				//
				readsize = gzread(f, &(tinfo.vtid), sizeof(int64_t));
				CHECK_READ_SIZE(readsize, sizeof(uint64_t));

				totreadsize += readsize;

				//
				// vpid
				//
				readsize = gzread(f, &(tinfo.vpid), sizeof(int64_t));
				CHECK_READ_SIZE(readsize, sizeof(uint64_t));

				totreadsize += readsize;

				//
				// cgroups
				//
				readsize = gzread(f, &(stlen), sizeof(uint16_t));
				CHECK_READ_SIZE(readsize, sizeof(uint16_t));

				if(stlen > SCAP_MAX_CGROUPS_SIZE)
				{
					snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid cgroupslen %d", stlen);
					return SCAP_FAILURE;
				}
				tinfo.cgroups_len = stlen;

				totreadsize += readsize;

				readsize = gzread(f, tinfo.cgroups, stlen);
				CHECK_READ_SIZE(readsize, stlen);

				totreadsize += readsize;

				if(block_type == PL_BLOCK_TYPE_V5 ||
				   block_type == PL_BLOCK_TYPE_V6)
				{
					readsize = gzread(f, &(stlen), sizeof(uint16_t));
					CHECK_READ_SIZE(readsize, sizeof(uint16_t));

					if(stlen > SCAP_MAX_PATH_SIZE)
					{
						snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid rootlen %d", stlen);
						return SCAP_FAILURE;
					}

					totreadsize += readsize;

					readsize = gzread(f, tinfo.root, stlen);
					CHECK_READ_SIZE(readsize, stlen);

					// the string is not null-terminated on file
					tinfo.root[stlen] = 0;

					totreadsize += readsize;
				}
			}
			break;
		default:
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		//
		// All parsed. Add the entry to the table, or fire the notification callback
		//
		if(handle->m_proc_callback == NULL)
		{
			//
			// All parsed. Allocate the new entry and copy the temp one into into it.
			//
			ntinfo = (scap_threadinfo *)malloc(sizeof(scap_threadinfo));
			if(ntinfo == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (fd1)");
				return SCAP_FAILURE;
			}

			// Structure copy
			*ntinfo = tinfo;

			HASH_ADD_INT64(handle->m_proclist, tid, ntinfo);
			if(uth_status != SCAP_SUCCESS)
			{
				free(ntinfo);
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (fd2)");
				return SCAP_FAILURE;
			}
		}
		else
		{
			handle->m_proc_callback(handle->m_proc_callback_context, tinfo.tid, &tinfo, NULL, handle);
		}
	}

	//
	// Read the padding bytes so we properly align to the end of the data
	//
	if(totreadsize > block_length)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = (size_t)gzread(f, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE(readsize, padding_len);

	return SCAP_SUCCESS;
}

//
// Parse an interface list block
//
static int32_t scap_read_iflist(scap_t *handle, gzFile f, uint32_t block_length)
{
	int32_t res = SCAP_SUCCESS;
	size_t readsize;
	size_t totreadsize;
	char *readbuf = NULL;
	char *pif;
	uint16_t iftype;
	uint16_t ifnamlen;
	uint32_t toread;
	uint32_t entrysize;
	uint32_t ifcnt4 = 0;
	uint32_t ifcnt6 = 0;

	//
	// If the list of interfaces was already allocated for this handle (for example because this is
	// not the first interface list block), free it
	//
	if(handle->m_addrlist != NULL)
	{
		scap_free_iflist(handle->m_addrlist);
		handle->m_addrlist = NULL;
	}

	//
	// Bring the block to memory
	// We assume that this block is always small enough that we can read it in a single shot
	//
	readbuf = (char *)malloc(block_length);
	if(!readbuf)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "memory allocation error in scap_read_iflist");
		return SCAP_FAILURE;
	}

	readsize = gzread(f, readbuf, block_length);
	CHECK_READ_SIZE(readsize, block_length);

	//
	// First pass, count the number of addresses
	//
	pif = readbuf;
	totreadsize = 0;

	while(true)
	{
		toread = (int32_t)block_length - (int32_t)totreadsize;

		if(toread < 4)
		{
			break;
		}

		iftype = *(uint16_t *)pif;
		ifnamlen = *(uint16_t *)(pif + 2);

		if(iftype == SCAP_II_IPV4)
		{
			entrysize = sizeof(scap_ifinfo_ipv4) + ifnamlen - SCAP_MAX_PATH_SIZE;
		}
		else if(iftype == SCAP_II_IPV6)
		{
			entrysize = sizeof(scap_ifinfo_ipv6) + ifnamlen - SCAP_MAX_PATH_SIZE;
		}
		else if(iftype == SCAP_II_IPV4_NOLINKSPEED)
		{
			entrysize = sizeof(scap_ifinfo_ipv4_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;
		}
		else if(iftype == SCAP_II_IPV6_NOLINKSPEED)
		{
			entrysize = sizeof(scap_ifinfo_ipv6_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;
		}
		else
		{
			ASSERT(false);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(1)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}

		if(toread < entrysize)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(2)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}

		pif += entrysize;
		totreadsize += entrysize;

		if(iftype == SCAP_II_IPV4 || iftype == SCAP_II_IPV4_NOLINKSPEED)
		{
			ifcnt4++;
		}
		else if(iftype == SCAP_II_IPV6 || iftype == SCAP_II_IPV6_NOLINKSPEED)
		{
			ifcnt6++;
		}
		else
		{
			ASSERT(false);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unknown interface type %d", (int)iftype);
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}

	//
	// Allocate the handle and the arrays
	//
	handle->m_addrlist = (scap_addrlist *)malloc(sizeof(scap_addrlist));
	if(!handle->m_addrlist)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_read_iflist allocation failed(1)");
		res = SCAP_FAILURE;
		goto scap_read_iflist_error;
	}

	handle->m_addrlist->n_v4_addrs = 0;
	handle->m_addrlist->n_v6_addrs = 0;
	handle->m_addrlist->v4list = NULL;
	handle->m_addrlist->v6list = NULL;
	handle->m_addrlist->totlen = block_length;

	if(ifcnt4 != 0)
	{
		handle->m_addrlist->v4list = (scap_ifinfo_ipv4 *)malloc(ifcnt4 * sizeof(scap_ifinfo_ipv4));
		if(!handle->m_addrlist->v4list)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_read_iflist allocation failed(2)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}
	else
	{
		handle->m_addrlist->v4list = NULL;
	}

	if(ifcnt6 != 0)
	{
		handle->m_addrlist->v6list = (scap_ifinfo_ipv6 *)malloc(ifcnt6 * sizeof(scap_ifinfo_ipv6));
		if(!handle->m_addrlist->v6list)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "getifaddrs allocation failed(3)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}
	else
	{
		handle->m_addrlist->v6list = NULL;
	}

	handle->m_addrlist->n_v4_addrs = ifcnt4;
	handle->m_addrlist->n_v6_addrs = ifcnt6;

	//
	// Second pass: populate the arrays
	//
	ifcnt4 = 0;
	ifcnt6 = 0;
	pif = readbuf;
	totreadsize = 0;

	while(true)
	{
		toread = (int32_t)block_length - (int32_t)totreadsize;

		if(toread < 4)
		{
			break;
		}

		iftype = *(uint16_t *)pif;
		ifnamlen = *(uint16_t *)(pif + 2);

		if(ifnamlen >= SCAP_MAX_PATH_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(0)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}

		if(iftype == SCAP_II_IPV4)
		{
			entrysize = sizeof(scap_ifinfo_ipv4) + ifnamlen - SCAP_MAX_PATH_SIZE;

			if(toread < entrysize)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(1)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			memcpy(handle->m_addrlist->v4list + ifcnt4, pif, entrysize);

			// Make sure the name string is NULL-terminated
			*((char *)(handle->m_addrlist->v4list + ifcnt4) + entrysize) = 0;

			pif += entrysize;
			totreadsize += entrysize;

			ifcnt4++;
		}
		else if(iftype == SCAP_II_IPV4_NOLINKSPEED)
		{
			scap_ifinfo_ipv4_nolinkspeed* src;
			scap_ifinfo_ipv4* dst;

			entrysize = sizeof(scap_ifinfo_ipv4_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;

			if(toread < entrysize)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(1)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			src = (scap_ifinfo_ipv4_nolinkspeed*)pif;
			dst = handle->m_addrlist->v4list + ifcnt4;

			dst->type = src->type;
			dst->ifnamelen = src->ifnamelen;
			dst->addr = src->addr;
			dst->netmask = src->netmask;
			dst->bcast = src->bcast;
			dst->linkspeed = 0;
			memcpy(dst->ifname, src->ifname, MIN(dst->ifnamelen, SCAP_MAX_PATH_SIZE - 1));

			// Make sure the name string is NULL-terminated
			*((char *)(dst->ifname + MIN(dst->ifnamelen, SCAP_MAX_PATH_SIZE - 1))) = 0;

			pif += entrysize;
			totreadsize += entrysize;

			ifcnt4++;
		}
		else if(iftype == SCAP_II_IPV6)
		{
			entrysize = sizeof(scap_ifinfo_ipv6) + ifnamlen - SCAP_MAX_PATH_SIZE;

			if(toread < entrysize)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(1)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			memcpy(handle->m_addrlist->v6list + ifcnt6, pif, entrysize);

			// Make sure the name string is NULL-terminated
			*((char *)(handle->m_addrlist->v6list + ifcnt6) + entrysize) = 0;

			pif += entrysize;
			totreadsize += entrysize;

			ifcnt6++;
		}
		else if(iftype == SCAP_II_IPV6_NOLINKSPEED)
		{
			scap_ifinfo_ipv6_nolinkspeed* src;
			scap_ifinfo_ipv6* dst;
			entrysize = sizeof(scap_ifinfo_ipv6_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;

			if(toread < entrysize)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(1)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			src = (scap_ifinfo_ipv6_nolinkspeed*)pif;
			dst = handle->m_addrlist->v6list + ifcnt6;

			dst->type = src->type;
			dst->ifnamelen = src->ifnamelen;
			memcpy(dst->addr, src->addr, SCAP_IPV6_ADDR_LEN);
			memcpy(dst->netmask, src->netmask, SCAP_IPV6_ADDR_LEN);
			memcpy(dst->bcast, src->bcast, SCAP_IPV6_ADDR_LEN);
			dst->linkspeed = 0;
			memcpy(dst->ifname, src->ifname, MIN(dst->ifnamelen, SCAP_MAX_PATH_SIZE - 1));

			// Make sure the name string is NULL-terminated
			*((char *)(dst->ifname + MIN(dst->ifnamelen, SCAP_MAX_PATH_SIZE - 1))) = 0;

			pif += entrysize;
			totreadsize += entrysize;

			ifcnt6++;
		}
		else
		{
			ASSERT(false);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unknown interface type %d", (int)iftype);
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}

	//
	// Release the read storage
	//
	free(readbuf);

	return res;

scap_read_iflist_error:
	scap_free_iflist(handle->m_addrlist);
	handle->m_addrlist = NULL;

	if(readbuf)
	{
		free(readbuf);
	}

	return res;
}

//
// Parse a user list block
//
static int32_t scap_read_userlist(scap_t *handle, gzFile f, uint32_t block_length)
{
	size_t readsize;
	size_t totreadsize = 0;
	size_t padding_len;
	uint32_t padding;
	uint8_t type;
	uint16_t stlen;

	//
	// If the list of users was already allocated for this handle (for example because this is
	// not the first interface list block), free it
	//
	if(handle->m_userlist != NULL)
	{
		scap_free_userlist(handle->m_userlist);
		handle->m_userlist = NULL;
	}

	//
	// Allocate and initialize the handle info
	//
	handle->m_userlist = (scap_userlist*)malloc(sizeof(scap_userlist));
	if(handle->m_userlist == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(2)");
		return SCAP_FAILURE;
	}

	handle->m_userlist->nusers = 0;
	handle->m_userlist->ngroups = 0;
	handle->m_userlist->totsavelen = 0;
	handle->m_userlist->users = NULL;
	handle->m_userlist->groups = NULL;

	//
	// Import the blocks
	//
	while(((int32_t)block_length - (int32_t)totreadsize) >= 4)
	{
		//
		// type
		//
		readsize = gzread(f, &(type), sizeof(type));
		CHECK_READ_SIZE(readsize, sizeof(type));

		totreadsize += readsize;

		if(type == USERBLOCK_TYPE_USER)
		{
			scap_userinfo* puser;

			handle->m_userlist->nusers++;
			handle->m_userlist->users = (scap_userinfo*)realloc(handle->m_userlist->users, handle->m_userlist->nusers * sizeof(scap_userinfo));
			if(handle->m_userlist->users == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "memory allocation error in scap_read_userlist(1)");
				return SCAP_FAILURE;
			}

			puser = &handle->m_userlist->users[handle->m_userlist->nusers -1];

			//
			// uid
			//
			readsize = gzread(f, &(puser->uid), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			totreadsize += readsize;

			//
			// gid
			//
			readsize = gzread(f, &(puser->gid), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			totreadsize += readsize;

			//
			// name
			//
			readsize = gzread(f, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE(readsize, sizeof(uint16_t));

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid user name len %d", stlen);
				return SCAP_FAILURE;
			}

			totreadsize += readsize;

			readsize = gzread(f, puser->name, stlen);
			CHECK_READ_SIZE(readsize, stlen);

			// the string is not null-terminated on file
			puser->name[stlen] = 0;

			totreadsize += readsize;

			//
			// homedir
			//
			readsize = gzread(f, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE(readsize, sizeof(uint16_t));

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid user homedir len %d", stlen);
				return SCAP_FAILURE;
			}

			totreadsize += readsize;

			readsize = gzread(f, puser->homedir, stlen);
			CHECK_READ_SIZE(readsize, stlen);

			// the string is not null-terminated on file
			puser->homedir[stlen] = 0;

			totreadsize += readsize;

			//
			// shell
			//
			readsize = gzread(f, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE(readsize, sizeof(uint16_t));

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid user shell len %d", stlen);
				return SCAP_FAILURE;
			}

			totreadsize += readsize;

			readsize = gzread(f, puser->shell, stlen);
			CHECK_READ_SIZE(readsize, stlen);

			// the string is not null-terminated on file
			puser->shell[stlen] = 0;

			totreadsize += readsize;
		}
		else
		{
			scap_groupinfo* pgroup;

			handle->m_userlist->ngroups++;
			handle->m_userlist->groups = (scap_groupinfo*)realloc(handle->m_userlist->groups, handle->m_userlist->ngroups * sizeof(scap_groupinfo));
			if(handle->m_userlist->groups == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "memory allocation error in scap_read_userlist(2)");
				return SCAP_FAILURE;
			}

			pgroup = &handle->m_userlist->groups[handle->m_userlist->ngroups -1];

			//
			// gid
			//
			readsize = gzread(f, &(pgroup->gid), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			totreadsize += readsize;

			//
			// name
			//
			readsize = gzread(f, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE(readsize, sizeof(uint16_t));

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid group name len %d", stlen);
				return SCAP_FAILURE;
			}

			totreadsize += readsize;

			readsize = gzread(f, pgroup->name, stlen);
			CHECK_READ_SIZE(readsize, stlen);

			// the string is not null-terminated on file
			pgroup->name[stlen] = 0;

			totreadsize += readsize;
		}
	}

	//
	// Read the padding bytes so we properly align to the end of the data
	//
	if(totreadsize > block_length)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = gzread(f, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE(readsize, padding_len);

	return SCAP_SUCCESS;
}

//
// Parse a process list block
//
static int32_t scap_read_fdlist(scap_t *handle, gzFile f, uint32_t block_length)
{
	size_t readsize;
	size_t totreadsize = 0;
	size_t padding_len;
	struct scap_threadinfo *tinfo;
	scap_fdinfo fdi;
	scap_fdinfo *nfdi;
	//  uint16_t stlen;
	uint64_t tid;
	int32_t uth_status = SCAP_SUCCESS;
	uint32_t padding;

	//
	// Read the tid
	//
	readsize = gzread(f, &tid, sizeof(tid));
	CHECK_READ_SIZE(readsize, sizeof(tid));
	totreadsize += readsize;

	if(handle->m_proc_callback == NULL)
	{
		//
		// Identify the process descriptor
		//
		HASH_FIND_INT64(handle->m_proclist, &tid, tinfo);
		if(tinfo == NULL)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted trace file. FD block references TID %"PRIu64", which doesn't exist.",
					 tid);
			return SCAP_FAILURE;
		}
	}
	else
	{
		tinfo = NULL;
	}

	while(((int32_t)block_length - (int32_t)totreadsize) >= 4)
	{
		if(scap_fd_read_from_disk(handle, &fdi, &readsize, f) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}
		totreadsize += readsize;

		//
		// Add the entry to the table, or fire the notification callback
		//
		if(handle->m_proc_callback == NULL)
		{
			//
			// Parsed successfully. Allocate the new entry and copy the temp one into into it.
			//
			nfdi = (scap_fdinfo *)malloc(sizeof(scap_fdinfo));
			if(nfdi == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (fd1)");
				return SCAP_FAILURE;
			}

			// Structure copy
			*nfdi = fdi;

			ASSERT(tinfo != NULL);

			HASH_ADD_INT64(tinfo->fdlist, fd, nfdi);
			if(uth_status != SCAP_SUCCESS)
			{
				free(nfdi);
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (fd2)");
				return SCAP_FAILURE;
			}
		}
		else
		{
			ASSERT(tinfo == NULL);

			handle->m_proc_callback(handle->m_proc_callback_context, tid, NULL, &fdi, handle);
		}
	}

	//
	// Read the padding bytes so we properly align to the end of the data
	//
	if(totreadsize > block_length)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = gzread(f, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE(readsize, padding_len);

	return SCAP_SUCCESS;
}

//
// Parse the headers of a trace file and load the tables
//
int32_t scap_read_init(scap_t *handle, gzFile f)
{
	block_header bh;
	section_header_block sh;
	uint32_t bt;
	size_t readsize;
	size_t toread;
	int fseekres;
	int8_t found_mi = 0;
	int8_t found_pl = 0;
	int8_t found_fdl = 0;
	int8_t found_il = 0;
	int8_t found_ul = 0;
	int8_t found_ev = 0;

	//
	// Read the section header block
	//
	if(gzread(f, &bh, sizeof(bh)) != sizeof(bh) ||
	        gzread(f, &sh, sizeof(sh)) != sizeof(sh) ||
	        gzread(f, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	if(bh.block_type != SHB_BLOCK_TYPE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid block type");
		return SCAP_FAILURE;
	}

	if(sh.byte_order_magic != 0x1a2b3c4d)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid magic number");
		return SCAP_FAILURE;
	}

	//
	// Read the metadata blocks (processes, FDs, etc.)
	//
	while(true)
	{
		readsize = gzread(f, &bh, sizeof(bh));

		//
		// If we don't find the event block header,
		// it means there is no event in the file.
		//
		if (readsize == 0 && !found_ev && found_mi && found_pl &&
			found_il && found_fdl && found_ul)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "no events in file");
			return SCAP_FAILURE;
		}

		CHECK_READ_SIZE(readsize, sizeof(bh));

		switch(bh.block_type)
		{
		case MI_BLOCK_TYPE:
		case MI_BLOCK_TYPE_INT:
			found_mi = 1;

			if(scap_read_machine_info(handle, f, bh.block_total_length - sizeof(block_header) - 4) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3_INT:
			found_pl = 1;

			if(scap_read_proclist(handle, f, bh.block_total_length - sizeof(block_header) - 4, bh.block_type) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case FDL_BLOCK_TYPE:
		case FDL_BLOCK_TYPE_INT:
			found_fdl = 1;

			if(scap_read_fdlist(handle, f, bh.block_total_length - sizeof(block_header) - 4) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case EV_BLOCK_TYPE:
		case EV_BLOCK_TYPE_INT:
		case EVF_BLOCK_TYPE:
			found_ev = 1;

			//
			// We're done with the metadata headers. Rewind the file position so we are aligned to start reading the events.
			//
			fseekres = gzseek(f, (long)0 - sizeof(bh), SEEK_CUR);
			if(fseekres != -1)
			{
				break;
			}
			else
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error seeking in file");
				return SCAP_FAILURE;
			}
		case IL_BLOCK_TYPE:
		case IL_BLOCK_TYPE_INT:
			found_il = 1;

			if(scap_read_iflist(handle, f, bh.block_total_length - sizeof(block_header) - 4) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case UL_BLOCK_TYPE:
		case UL_BLOCK_TYPE_INT:
			found_ul = 1;

			if(scap_read_userlist(handle, f, bh.block_total_length - sizeof(block_header) - 4) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		default:
			//
			// Unknwon block type. Skip the block.
			//
			toread = bh.block_total_length - sizeof(block_header) - 4;
			fseekres = (int)gzseek(f, (long)toread, SEEK_CUR);
			if(fseekres == -1)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip block of type %x and size %u.",
				         (int)bh.block_type,
				         (unsigned int)toread);
				return SCAP_FAILURE;
			}
			break;
		}

		if(found_ev)
		{
			break;
		}

		//
		// Read and validate the trailer
		//
		readsize = gzread(f, &bt, sizeof(bt));
		CHECK_READ_SIZE(readsize, sizeof(bt));

		if(bt != bh.block_total_length)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "wrong block total length, header=%u, trailer=%u",
			         bh.block_total_length,
			         bt);
			return SCAP_FAILURE;
		}
	}

	if(!found_mi)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Can't find machine info block.");
		return SCAP_FAILURE;
	}

	if(!found_ul)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Can't find user list block.");
		return SCAP_FAILURE;
	}

	if(!found_il)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Can't find interface list block.");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Read an event from disk
//
int32_t scap_next_offline(scap_t *handle, OUT scap_evt **pevent, OUT uint16_t *pcpuid)
{
	block_header bh;
	size_t readsize;
	uint32_t readlen;
	gzFile f = handle->m_file;

	ASSERT(f != NULL);

	//
	// Read the block header
	//
	readsize = gzread(f, &bh, sizeof(bh));

	if(readsize != sizeof(bh))
	{
		int err_no = 0;
		const char* err_str = gzerror(f, &err_no);
		if(err_no)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading file: %s, ernum=%d", err_str, err_no);
			return SCAP_FAILURE;
		}

		if(readsize == 0)
		{
			//
			// We read exactly 0 bytes. This indicates a correct end of file.
			//
			return SCAP_EOF;
		}
		else
		{
			CHECK_READ_SIZE(readsize, sizeof(bh));
		}
	}

	if(bh.block_type != EV_BLOCK_TYPE &&
		bh.block_type != EV_BLOCK_TYPE_INT &&
		bh.block_type != EVF_BLOCK_TYPE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unexpected block type %u", (uint32_t)bh.block_type);
		return SCAP_FAILURE;
	}

	if(bh.block_total_length < sizeof(bh) + sizeof(struct ppm_evt_hdr) + 4)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "block length too short %u", (uint32_t)bh.block_total_length);
		return SCAP_FAILURE;
	}

	//
	// Read the event
	//
	readlen = bh.block_total_length - sizeof(bh);
	if (readlen > FILE_READ_BUF_SIZE) {
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event block length %u greater than read buffer size %u",
			 readlen,
			 FILE_READ_BUF_SIZE);
		return SCAP_FAILURE;
	}

	readsize = gzread(f, handle->m_file_evt_buf, readlen);
	CHECK_READ_SIZE(readsize, readlen);

	//
	// EVF_BLOCK_TYPE has 32 bits of flags
	//
	*pcpuid = *(uint16_t *)handle->m_file_evt_buf;

	if(bh.block_type == EVF_BLOCK_TYPE)
	{
		handle->m_last_evt_dump_flags = *(uint32_t*)(handle->m_file_evt_buf + sizeof(uint16_t));
		*pevent = (struct ppm_evt_hdr *)(handle->m_file_evt_buf + sizeof(uint16_t) + sizeof(uint32_t));
	}
	else
	{
		handle->m_last_evt_dump_flags = 0;
		*pevent = (struct ppm_evt_hdr *)(handle->m_file_evt_buf + sizeof(uint16_t));
	}

	return SCAP_SUCCESS;
}

uint64_t scap_ftell(scap_t *handle)
{
	gzFile f = handle->m_file;
	ASSERT(f != NULL);

	return gztell(f);
}

void scap_fseek(scap_t *handle, uint64_t off)
{
	gzFile f = handle->m_file;
	ASSERT(f != NULL);

	gzseek(f, off, SEEK_SET);
}
