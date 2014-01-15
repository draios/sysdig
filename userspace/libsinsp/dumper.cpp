#include "sinsp.h"
#include "sinsp_int.h"
#include "../libscap/scap.h"
#include "dumper.h"

sinsp_dumper::sinsp_dumper(sinsp* inspector)
{
	m_inspector = inspector;
	m_dumper = NULL;
}

sinsp_dumper::~sinsp_dumper()
{
	if(m_dumper != NULL)
	{
		scap_dump_close(m_dumper);
	}
}

void sinsp_dumper::open(const string& filename)
{
	if(m_inspector->m_h == NULL)
	{
		throw sinsp_exception("can't start event dump, inspector not opened yet");
	}

	m_dumper = scap_dump_open(m_inspector->m_h, filename.c_str());
	if(m_dumper == NULL)
	{
		throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
	}
}

void sinsp_dumper::dump(sinsp_evt* evt)
{
	if(m_dumper == NULL)
	{
		throw sinsp_exception("dumper not opened yet");
	}

	int32_t res = scap_dump(m_inspector->m_h, 
		m_dumper, evt->m_pevt, evt->m_cpuid);

	if(res != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
	}
}
