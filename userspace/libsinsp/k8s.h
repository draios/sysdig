//
// k8s.h
//
// extracts needed data from the k8s REST API interface
//

#pragma once

#include "json/json.h"
#include "k8s_common.h"
#include "k8s_component.h"
#include "k8s_state.h"
#include "k8s_event_data.h"
#include "k8s_net.h"
#include "sinsp_curl.h"
#include <sstream>
#include <utility>

class k8s_dispatcher;

class k8s
{
public:
#ifdef HAS_CAPTURE
	typedef sinsp_curl::ssl::ptr_t          ssl_ptr_t;
	typedef sinsp_curl::bearer_token::ptr_t bt_ptr_t;
#endif // HAS_CAPTURE

	k8s(const std::string& uri = "http://localhost:80",
		bool start_watch = false,
		bool watch_in_thread = false,
		bool is_captured = false,
		const std::string& api = "/api/v1/",
#ifdef HAS_CAPTURE
		ssl_ptr_t ssl = 0,
		bt_ptr_t bt = 0,
#endif // HAS_CAPTURE
		bool curl_debug = false);

	~k8s();

	std::size_t count(k8s_component::type component) const;

	void on_watch_data(k8s_event_data&& msg);

	const k8s_state_t& get_state(bool rebuild = false);

	bool watch_in_thread() const;

	void watch();

	void stop_watching();

	bool is_alive() const;

#ifdef HAS_CAPTURE
	typedef k8s_state_t::event_list_t event_list_t;
	const event_list_t& get_capture_events() const { return m_state.get_capture_events(); }
	std::string dequeue_capture_event() { return m_state.dequeue_capture_event(); }
#endif // HAS_CAPTURE

	void simulate_watch_event(const std::string& json);

private:
	void extract_data(Json::Value& items, k8s_component::type component, const std::string& api_version);

	void build_state();

	void parse_json(const std::string& json, const k8s_component::component_map::value_type& component);

	void stop_watch();

	void cleanup();

	// due to deleted default dispatcher constructor, g++ has trouble instantiating map with values,
	// so we have to go with the forward declaration above and pointers here ...
	typedef std::map<k8s_component::type, k8s_dispatcher*> dispatch_map;

#ifdef K8S_DISABLE_THREAD
	static dispatch_map make_dispatch_map(k8s_state_t& state);
#else
	static dispatch_map make_dispatch_map(k8s_state_t& state, std::mutex& mut);
#endif // K8S_DISABLE_THREAD

	K8S_DECLARE_MUTEX;
	bool         m_watch;
	bool         m_watch_in_thread;
	k8s_state_t  m_state;
	dispatch_map m_dispatch;
#ifdef HAS_CAPTURE
	k8s_net*     m_net;
#endif

	static const k8s_component::component_map m_components;
	friend class k8s_test;
};

inline bool k8s::watch_in_thread() const
{
	return m_watch_in_thread;
}

inline bool k8s::is_alive() const
{
#ifdef HAS_CAPTURE
	ASSERT(m_net);
	return m_net->is_healthy() && m_net->is_watching();
#endif
	return true;
}

