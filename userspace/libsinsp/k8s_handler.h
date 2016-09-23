//
// k8s_handler.h
//

#pragma once

#include "json/json.h"
#include "socket_collector.h"
#include "k8s_state.h"
#include "k8s_api_error.h"
#include <unordered_set>

class sinsp;

class k8s_handler
{
public:
	typedef k8s_component::msg_reason msg_reason;
	typedef k8s_component::msg_data msg_data;

	typedef std::shared_ptr<k8s_handler>     ptr_t;
	typedef std::vector<std::string>         uri_list_t;
	typedef std::shared_ptr<Json::Value>     json_ptr_t;
	typedef sinsp_ssl::ptr_t                 ssl_ptr_t;
	typedef sinsp_bearer_token::ptr_t        bt_ptr_t;
	typedef socket_data_handler<k8s_handler> handler_t;
	typedef handler_t::ptr_t                 handler_ptr_t;
	typedef socket_collector<handler_t>      collector_t;
	typedef std::shared_ptr<socket_collector<handler_t>>      collector_ptr_t;
	typedef std::shared_ptr<k8s_api_error>   api_error_ptr;

	static const int default_timeout_ms = 1000L;

	k8s_handler(const std::string& id,
		bool is_captured,
		std::string url,
		const std::string& path,
		const std::string& state_filter,
		const std::string& event_filter,
		collector_ptr_t collector = nullptr,
		const std::string& http_version = "1.0",
		int timeout_ms = default_timeout_ms,
		ssl_ptr_t ssl = nullptr,
		bt_ptr_t bt = nullptr,
		k8s_state_t* state = nullptr,
		bool watch = true,
		bool connect = true);

	virtual ~k8s_handler();

	bool connection_error() const;
	bool is_alive() const;
	void set_event_json(json_ptr_t json, const std::string&);
	const std::string& get_id() const;

	void collect_data();
	void set_machine_id(const std::string& machine_id);
	const std::string& get_machine_id() const;

	bool is_state_built() const;

	handler_ptr_t handler();

	std::string name() const;

	api_error_ptr error() const;

	virtual void handle_json(Json::Value&& root);

protected:
	typedef std::unordered_set<std::string> ip_addr_list_t;

	virtual bool handle_component(const Json::Value& json, const msg_data* data = 0) = 0;
	msg_data get_msg_data(const std::string& evt, const std::string& type, const Json::Value& root);
	static bool is_ip_address(const std::string& addr);

	k8s_pair_list extract_object(const Json::Value& object);

	template <typename T>
	void handle_selectors(T& component, const Json::Value& selector)
	{
		if(!selector.isNull())
		{
			component.set_selectors(extract_object(selector));
		}
		else
		{
			g_logger.log("K8s Replication Controller: Null selector object.", sinsp_logger::SEV_ERROR);
		}
	}

	void log_event(const msg_data& data);
	void handle_error(const msg_data& data, const Json::Value& root, bool log = true);
	void log_error(const msg_data& data, const Json::Value& root);
	void log_not_found(const msg_data& data) const;

	k8s_state_t* m_state = nullptr;

	static std::string ERROR_FILTER;

private:
	typedef void (k8s_handler::*callback_func_t)(json_ptr_t, const std::string&);

	typedef std::vector<json_ptr_t> event_list_t;

	static ip_addr_list_t hostname_to_ip(const std::string& hostname);

	bool connect();
	void make_http();
	void send_data_request();
	void check_enabled();
	void check_state();
	void check_collector_status();
	void process_events();

	const std::string& translate_name(const std::string& event_name);

	collector_ptr_t m_collector;
	handler_ptr_t   m_http;
	std::string     m_id;
	std::string     m_path;
	std::string     m_state_filter;
	std::string     m_event_filter;
	std::string&    m_filter;
	std::string     m_event_uri;
	event_list_t    m_events;
	long            m_timeout_ms;
	std::string     m_machine_id;
	json_query      m_jq;
	std::string     m_url;
	std::string     m_http_version;
	ssl_ptr_t       m_ssl;
	bt_ptr_t        m_bt;
	bool            m_req_sent = false;
	bool            m_state_built = false;

	// some handlers only fetch state and die by design (eg. api or extensions handlers
	// have no need to continuously watch for updates)
	// this flag indicates whether handler should continue to watch after receiving
	// the initial state
	bool m_watch;

	// flag indicating whether to connect to K8s API server (no connection needed when
	// replaying capture)
	bool m_connect;

	// error indicating something went wrong with the K8s component handled by this handler
	// this error is later examined by k8s::check_components() and if it is
	// HTTP status > 400, one of the following actions is taken:
	//  - if component is critical for consistent k8s state (eg. namepace, node, pod),
	//    exception is thrown and, consequently, the whole k8s framework will be destroyed
	//  - if component is not critical (eg. extensions like daemonset or deployment),
	//    error is logged and handler is destroyed, but the k8s framework continues to
	//    exist without it, only receiving data for existing components
	api_error_ptr m_error;

	// this capture flag does not indicate whether we are in global capture mode,
	// it is only an indication of whether this handler data should be captured
	// at all (eg. there is no need to capture api or extensions detection data)
	//
	// global capture flag is checked in the k8s state call
	bool m_is_captured = false;
};

inline k8s_handler::handler_ptr_t k8s_handler::handler()
{
	return m_http;
}

inline const std::string& k8s_handler::get_id() const
{
	return m_id;
}

inline void k8s_handler::set_machine_id(const std::string& machine_id)
{
	m_machine_id = machine_id;
}

inline const std::string& k8s_handler::get_machine_id() const
{
	return m_machine_id;
}

inline bool k8s_handler::is_state_built() const
{
	return m_state_built;
}

inline void k8s_handler::log_event(const msg_data& data)
{
	g_logger.log("K8s " + data.get_reason_desc() + ' ' +
				 data.m_kind + ' ' +
				 data.m_name + " [" + data.m_uid + "]",
				 sinsp_logger::SEV_DEBUG);
}

inline void k8s_handler::log_not_found(const msg_data& data) const
{
	g_logger.log("K8s " + name() + " not found [" + data.m_uid + "]: " + data.m_name,
				 sinsp_logger::SEV_ERROR);
}

inline k8s_handler::api_error_ptr k8s_handler::error() const
{
	return m_error;
}
