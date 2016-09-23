//
// k8s_node_handler.cpp
//

#include "k8s_node_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-node array, state is turned into ADDED event

std::string k8s_node_handler::EVENT_FILTER =
	"{"
	" type: .type,"
	" apiVersion: .object.apiVersion,"
	" kind: .object.kind,"
	" items:"
	" ["
	"  .object |"
	"  {"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   labels: .metadata.labels,"
	"   addresses: [.status.addresses[].address] | unique"
	"  }"
	" ]"
	"}";

std::string k8s_node_handler::STATE_FILTER =
	"{"
	" type: \"ADDED\","
	" apiVersion: .apiVersion,"
	" kind: \"Node\", "
	" items:"
	" ["
	"  .items[] | "
	"  {"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   labels: .metadata.labels,"
	"   addresses: [.status.addresses[].address] | unique"
	"   }"
	" ]"
	"}";

k8s_node_handler::k8s_node_handler(k8s_state_t& state,
	std::string url,
	const std::string& http_version,
	ssl_ptr_t ssl,
	bt_ptr_t bt):
		k8s_handler("k8s_node_handler", url, "/api/v1/nodes",
					STATE_FILTER, EVENT_FILTER, http_version,
					1000L, ssl, bt, &state)
{
}

k8s_node_handler::~k8s_node_handler()
{
}

void k8s_node_handler::handle_component(const Json::Value& json, const msg_data* data)
{
	if(data)
	{
		if(m_state)
		{
			k8s_node_t& node =
				m_state->get_component<k8s_nodes, k8s_node_t>(m_state->get_nodes(),
															  data->m_name, data->m_uid);
			k8s_node_t::host_ip_list addresses;
			k8s_component::extract_string_array(json["addresses"], addresses);
			if(addresses.size() > 0)
			{
				node.set_host_ips(std::move(addresses));
			}
			else
			{
				g_logger.log("K8s Node handler: Can not obtain IP address(es) for node" + data->m_name +
							 '[' + data->m_uid + ']', sinsp_logger::SEV_ERROR);
			}
			k8s_pair_list entries = k8s_component::extract_object(json, "labels");
			if(entries.size() > 0)
			{
				node.set_labels(std::move(entries));
			}
		}
		else
		{
			throw sinsp_exception("K8s node handler: state is null.");
		}
	}
	else
	{
		throw sinsp_exception("K8s node handler: data is null.");
	}
}
