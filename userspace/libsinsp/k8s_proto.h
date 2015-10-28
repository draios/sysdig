//
// k8s_proto.h
//
// extracts needed data from the k8s_proto REST API interface
//

#pragma once

#include "draios.pb.h"
#include "google/protobuf/text_format.h"

class k8s_state_s;

class k8s_proto
{
public:
	k8s_proto(draiosproto::metrics& metrics);

	~k8s_proto();

	const draiosproto::k8s_state& get_proto(const k8s_state_s& state);

private:
	void make_protobuf(const k8s_state_s& state);

	template <typename V, typename C>
	void populate_component(V& component, C* k8s_component)
	{
		draiosproto::k8s_common* common = k8s_component->mutable_common();
		common->set_name(component.get_name());
		common->set_uid(component.get_uid());
		const std::string ns = component.get_namespace();
		if(!ns.empty())
		{
			common->set_namespace_(ns);
		}

		for (auto label : component.get_labels())
		{
			draiosproto::k8s_pair* lbl = common->add_labels();
			lbl->set_key(label.first);
			lbl->set_value(label.second);
		}

		for (auto selector : component.get_selectors())
		{
			draiosproto::k8s_pair* sel = common->add_selectors();
			sel->set_key(selector.first);
			sel->set_value(selector.second);
		}
	}
	
	draiosproto::k8s_state& m_proto;
};
