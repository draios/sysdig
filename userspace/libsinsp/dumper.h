#pragma once

class sinsp;
class sinsp_evt;

class SINSP_PUBLIC sinsp_dumper
{
public:
	sinsp_dumper(sinsp* inspector);
	~sinsp_dumper();
	void open(const string& filename);
	void dump(sinsp_evt* evt);

private:
	sinsp* m_inspector;
	scap_dumper_t* m_dumper;
};

