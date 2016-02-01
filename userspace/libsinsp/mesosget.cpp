//
// mesosget.cpp
//
// extracts needed data from the mesos REST API interface,
// translates it to protobuf and prints the result in human readable format
//
// usage: mesosget [http://localhost:80] [v1]
//

#include "sinsp.h"
#include "mesos_proto.h"
#include "mesos_common.h"
#include "mesos_http.h"
#include "mesos.h"
#include "Poco/FileStream.h"
#include <unistd.h>

using namespace Poco;

sinsp_logger g_logger;

void print_groups(const ::google::protobuf::RepeatedPtrField< ::draiosproto::marathon_group >& groups)
{
	for(auto group : groups)
	{
		std::cout << group.id() << std::endl;
		for(const auto& app : group.apps())
		{
			std::cout << '\t' << app.id() << std::endl;
			for(const auto& task : app.task_ids())
			{
				std::cout << "\t\t" <<  task << std::endl;
			}
		}
		for(auto subgroup : group.groups())
		{
			print_groups(groups);
		}
	}
}

void print_proto(mesos& m, const std::string& fname)
{
	draiosproto::metrics met;
	mesos_proto(met).get_proto(m.get_state());
	//FileOutputStream fos("/home/alex/sysdig/agent/experiments/mesos/" + fname + ".protodump");
	//fos << met.DebugString();
	std::cout << met.DebugString() << std::endl;
	//std::cout << "++++" << std::endl;
	//print_groups(met.mesos().groups());
	//std::cout << "----" << std::endl;
}

int main(int argc, char** argv)
{
	std::string ip_addr = "52.90.231.127";
	std::vector<std::string> marathon_uris;
	marathon_uris.push_back("http://" + ip_addr + ":8080");
	mesos m("http://" + ip_addr + ":5050", "/master/state", 
		marathon_uris,
		mesos::default_groups_api,
		mesos::default_apps_api,
		mesos::default_watch_api);

	//print_proto(m, ip_addr);

	//m.refresh(true);
	//print_proto(m, ip_addr);
	while(true)
	{
		//print_proto(m, ip_addr);
		m.refresh(false);
		m.watch();
		sleep(5);
	}

	return 0;
}
