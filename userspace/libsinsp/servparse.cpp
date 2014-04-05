/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "servparse.h"

// To get the installation directory
#include "config.h"

#include <unordered_map>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>

#define	MAXALIASES	35
struct servent {
	char *s_name;     /*%< official service name */
	char **s_aliases; /*%< alias list */
	int s_port;       /*%< port # */
	char *s_proto;    /*%< protocol to use */
};

#if defined SINSP_PUBLIC
	static char SERVDB[] = SYSDIG_SHARE_DIR "/services";
	static char SERVDBUSER[] = SYSDIG_SHARE_DIR "/services-user";
#else
	static char SERVDB[] = "services";
	static char SERVDBUSER[] = "services-user";
#endif

#ifdef _WIN32
	// TODO: There is a better way of doing this, I'm sure
	static char SERVDBOS[] = "\\windows\\system32\\drivers\\etc\\services";
#else
	static char SERVDBOS[] = "/etc/services";
#endif

static FILE *servf = NULL;
static char line[BUFSIZ+1];
static struct servent serv;
static char *serv_aliases[MAXALIASES];
int _loaded = 0;

unordered_map<string,int> byName;
unordered_map<int,string> byPortTCP;
unordered_map<int,string> byPortUDP;

void useFile(char* fname)
{
	if (servf != NULL) 
	{
		fclose(servf);
	}

	// We handle an invalid file by testing the size
	// of the table.
	servf = fopen(fname, "r" );
}

struct servent * getservent()
{
	char *p;
	register char *cp, **q;

	if(servf == NULL)
	{
		return (NULL);
	}

again:
	if ((p = fgets(line, BUFSIZ, servf)) == NULL)
	{
		fclose(servf);
		servf = NULL;
		return (NULL);
	}

	if (*p == '#')
	{
		goto again;
	}

	cp = strpbrk(p, "#\n");
	if (cp == NULL)
	{
		goto again;
	}

	*cp = '\0';
	serv.s_name = p;

	p = strpbrk(p, " \t");
	if (p == NULL)
	{
		goto again;
	}
	*p++ = '\0';

	while (*p == ' ' || *p == '\t')
	{
		p++;
	}

	cp = strpbrk(p, ",/");
	if (cp == NULL)
	{
		goto again;
	}

	*cp++ = '\0';
	serv.s_port = (u_short)atoi(p);
	serv.s_proto = cp;
	q = serv.s_aliases = serv_aliases;
	cp = strpbrk(cp, " \t");

	if (cp != NULL)
	{
		*cp++ = '\0';
	}

	while (cp && *cp) 
	{
		if (*cp == ' ' || *cp == '\t') 
		{
			cp++;
			continue;
		}

		if (q < &serv_aliases[MAXALIASES - 1])
		{
			*q++ = cp;
		}
		cp = strpbrk(cp, " \t");
		if (cp != NULL)
		{
			*cp++ = '\0';
		}
	}

	*q = NULL;
	return (&serv);
}

int insert(servent *sd) 
{
	if(!sd)
	{
		return 0;
	}
	if(sd->s_proto[0] == 't') 
	{
		byPortTCP[sd->s_port] = string(sd->s_name);
	} 
	else if(sd->s_proto[0] == 'u') 
	{
		byPortUDP[sd->s_port] = string(sd->s_name);
	}

	byName[sd->s_name] = sd->s_port;
	return 1;
}

void loadFile() 
{
	if (!_loaded)
	{
		// Use the OS as the first line of defense.
		useFile(SERVDBOS);
		while(insert(getservent()));

		// The sysdig provided one can overwrite the OS values
		useFile(SERVDB);
		while(insert(getservent()));

		// And finally, the user provided one can overwrite anything.
		useFile(SERVDBUSER);
		while(insert(getservent()));

		_loaded = 1;
	}
}

string service::findByPort(int port, string type = "tcp") 
{
	loadFile();

	return ( (type[0] | 0x20) == 'u') ?
		byPortUDP[port] :
		byPortTCP[port];
		
}

int service::findByName(string name) 
{
	loadFile();
	int ix = byName[name];

	if (ix == 0)
	{
		throw sinsp_exception(
			"'" + string(name) + "' can't be translated to a port using any of the following services(5) files:\n\n" + 
			"  * " + string(SERVDB) + "\n" +
			"  * " + string(SERVDBUSER) + "\n" +
			"  * " + string(SERVDBOS) + "\n" +
			"\n" +
			"You can manually add the '" + string(name) + "' service to a file named " + string(SERVDBUSER) + "\n" +
			"Use the syntax of " + string(SERVDB) + " as a guide and try again.\n\n" +
			"Note: The entries in " +  string(SERVDBUSER) + " will be preserved on subsequent upgrades.");
	}

	return ix;
}

string service::toName(string in)
{
	return ( !in.empty() && strspn( in.c_str(), "0123456789" ) == in.size() ) 
		?  loadFile(), byPortTCP[stoi(in)]
		:  in;
}

int service::toPort(string in)
{
	return in.empty() ? 0 : (
		( strspn( in.c_str(), "0123456789" ) == in.size() )
			? stoi(in)
			: service::findByName(in)
		);
}

