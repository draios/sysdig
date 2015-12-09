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

#include <stdio.h>
#include "scap.h"
#include "scap-int.h"

#if defined(HAS_CAPTURE)
#include <sys/types.h>

#include <pwd.h>
#include <grp.h>

//
// Allocate and return the list of interfaces on this system
//
int32_t scap_create_userlist(scap_t* handle)
{
	uint32_t usercnt;
	uint32_t grpcnt;
	struct passwd *p;
	struct group *g;

	//
	// If the list of interfaces was already allocated for this handle (for example because this is
	// not the first interface list block), free it
	//
	if(handle->m_userlist != NULL)
	{
		scap_free_userlist(handle->m_userlist);
		handle->m_userlist = NULL;
	}

	//
	// First pass: count the number of users and the number of groups
	//
	p = getpwent();
	for(usercnt = 0; p; p = getpwent(), usercnt++); 
	endpwent();

	g = getgrent();
	for(grpcnt = 0; g; g = getgrent(), grpcnt++);
	endgrent();

	//
	// Memory allocations
	//
	handle->m_userlist = (scap_userlist*)malloc(sizeof(scap_userlist));
	if(handle->m_userlist == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(1)");
		return SCAP_FAILURE;
	}

	handle->m_userlist->nusers = usercnt;
	handle->m_userlist->ngroups = grpcnt;
	handle->m_userlist->totsavelen = 0;
	handle->m_userlist->users = (scap_userinfo*)malloc(usercnt * sizeof(scap_userinfo));
	if(handle->m_userlist->users == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(2)");
		free(handle->m_userlist);
		return SCAP_FAILURE;		
	}

	handle->m_userlist->groups = (scap_groupinfo*)malloc(grpcnt * sizeof(scap_groupinfo));
	if(handle->m_userlist->groups == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "grouplist allocation failed(2)");
		free(handle->m_userlist);
		free(handle->m_userlist->users);
		return SCAP_FAILURE;		
	}

	//
	// Second pass: copy the data
	//

	//users
	p = getpwent();

	for(usercnt = 0; p; p = getpwent(), usercnt++)
	{
		handle->m_userlist->users[usercnt].uid = p->pw_uid;
		handle->m_userlist->users[usercnt].gid = p->pw_gid;
		
		if(p->pw_name)
		{
			strncpy(handle->m_userlist->users[usercnt].name, p->pw_name, sizeof(handle->m_userlist->users[usercnt].name));
		}
		else
		{
			*handle->m_userlist->users[usercnt].name = '\0';
		}

		if(p->pw_dir)
		{
			strncpy(handle->m_userlist->users[usercnt].homedir, p->pw_dir, sizeof(handle->m_userlist->users[usercnt].homedir));
		}
		else
		{
			*handle->m_userlist->users[usercnt].homedir = '\0';	
		}

		if(p->pw_shell)
		{
			strncpy(handle->m_userlist->users[usercnt].shell, p->pw_shell, sizeof(handle->m_userlist->users[usercnt].shell));
		}
		else
		{
			*handle->m_userlist->users[usercnt].shell = '\0';	
		}

		handle->m_userlist->totsavelen += 
			sizeof(uint8_t) + // type
			sizeof(uint32_t) + // uid
			sizeof(uint32_t) +  // gid
			strlen(handle->m_userlist->users[usercnt].name) + 2 + 
			strlen(handle->m_userlist->users[usercnt].homedir) + 2 +
			strlen(handle->m_userlist->users[usercnt].shell) + 2; 
	}

	endpwent();

	// groups
	g = getgrent();

	for(grpcnt = 0; g; g = getgrent(), grpcnt++)
	{
		handle->m_userlist->groups[grpcnt].gid = g->gr_gid;

		if(g->gr_name)
		{
			strncpy(handle->m_userlist->groups[grpcnt].name, g->gr_name, sizeof(handle->m_userlist->groups[grpcnt].name));
		}
		else
		{
			*handle->m_userlist->groups[grpcnt].name = '\0';
		}

		handle->m_userlist->totsavelen += 
			sizeof(uint8_t) + // type
			sizeof(uint32_t) +  // gid
			strlen(handle->m_userlist->groups[grpcnt].name) + 2;
	}

	endgrent();

	return SCAP_SUCCESS;
}
#endif // HAS_CAPTURE

//
// Free a previously allocated list of users
//
void scap_free_userlist(scap_userlist* uhandle)
{
	if(uhandle)
	{
		free(uhandle->users);
		free(uhandle->groups);
		free(uhandle);
	}
}
