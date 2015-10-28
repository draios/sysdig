//
// k8s_proto.cpp
//

#include "k8s_proto.h"
#include "k8s_component.h"
#include "draios.pb.h"

using namespace draiosproto;

k8s_proto::k8s_proto(draiosproto::metrics& met) : m_proto(*met.mutable_kubernetes())
{
}

k8s_proto::~k8s_proto()
{
}

const draiosproto::k8s_state& k8s_proto::get_proto(const k8s_state_s& state)
{
	make_protobuf(state);
	return m_proto;
}

void k8s_proto::make_protobuf(const k8s_state_s& state)
{
	for (auto& ns : state.get_namespaces())
	{
		populate_component(ns, m_proto.add_namespaces());
	}

	for (auto& node : state.get_nodes())
	{
		k8s_node* nodes = m_proto.add_nodes();
		populate_component(node, nodes);
		for (auto& host_ip : node.get_host_ips())
		{
			auto host_ips = nodes->add_host_ips();
			host_ips->assign(host_ip.begin(), host_ip.end());
		}
	}

	for (auto& pod : state.get_pods())
	{
		k8s_pod* pods = m_proto.add_pods();
		populate_component(pod, pods);
		for (auto& container_id : pod.get_container_ids())
		{
			auto container_ids = pods->add_container_ids();
			container_ids->assign(container_id.begin(), container_id.end());
		}
		const std::string& nn = pod.get_node_name();
		if(!nn.empty())
		{
			pods->set_node_name(nn);
		}
		const std::string& hip = pod.get_host_ip();
		if(!hip.empty())
		{
			pods->set_host_ip(hip);
		}
		const std::string& ip = pod.get_internal_ip();
		if(!ip.empty())
		{
			pods->set_internal_ip(ip);
		}
	}

	for (auto& rc : state.get_rcs())
	{
		populate_component(rc, m_proto.add_controllers());
	}

	for (auto& service : state.get_services())
	{
		k8s_service* services = m_proto.add_services();
		populate_component(service, services);
		services->set_cluster_ip(service.get_cluster_ip());
		for (auto& port : service.get_port_list())
		{
			k8s_service_net_port* p = services->add_ports();
			p->set_port(port.m_port);
			p->set_target_port(port.m_target_port);
			if(!port.m_protocol.empty())
			{
				p->set_protocol(port.m_protocol);
			}
			if(port.m_node_port)
			{
				p->set_node_port(port.m_node_port);
			}
		}
	}
}
