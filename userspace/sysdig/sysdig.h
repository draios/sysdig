#pragma once

//
// The default output format
//
#define DEFAULT_OUTPUT_STR "*%evt.time %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args"

//
// ASSERT implementation
//
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

//
// Capture results
//
class captureinfo
{
public:
	captureinfo()
	{
		m_nevts = 0;
		m_time = 0;
	}

	uint64_t m_nevts;
	uint64_t m_time;
};
