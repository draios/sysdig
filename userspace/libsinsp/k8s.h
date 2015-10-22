//
// k8s.h
//
// extracts needed data from the k8s REST API interface
//

#pragma once

#include "json/json.h"
#include "k8s_common.h"
#include "k8s_component.h"
#include "k8s_event_data.h"
#include "k8s_net.h"
#include <sstream>
#include <utility>

class k8s_dispatcher;

class k8s
{
public:
	k8s(const std::string& uri = "http://localhost:80",
		bool start_watch = false,
		bool watch_in_thread = false,
		const std::string& api = "/api/v1/");

	~k8s();

	std::size_t count(k8s_component::type component) const;

	void on_watch_data(k8s_event_data&& msg);

	const k8s_state_s& get_state(bool rebuild = false);

	bool watch_in_thread() const;

	void watch();

	void stop_watching();

private:
	void extract_data(const Json::Value& items, k8s_component::type component);

	void build_state();

	void parse_json(const std::string& json, const k8s_component::component_map::value_type& component);

	// due to deleted default dispatcher constructor, g++ has trouble instantiating map with values,
	// so we have to go with the forward declaration above and pointers here ...
	typedef std::map<k8s_component::type, k8s_dispatcher*> dispatch_map;

#ifdef K8S_DISABLE_THREAD
	static dispatch_map make_dispatch_map(k8s_state_s& state);
#else
	static dispatch_map make_dispatch_map(k8s_state_s& state, std::mutex& mut);
#endif // K8S_DISABLE_THREAD

	K8S_DECLARE_MUTEX;
	bool         m_watch;
	bool         m_watch_in_thread;
	k8s_net      m_net;
	bool         m_own_proto;
	k8s_state_s  m_state;
	dispatch_map m_dispatch;
	
	static const k8s_component::component_map m_components;
};

inline bool k8s::watch_in_thread() const
{
	return m_watch_in_thread;
}
