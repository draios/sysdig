//
// k8s_component.h
//
// kubernetes components (nodes, namespaces, pods, replication controllers, services)
// abstraction
//

#pragma once

#include "json/json.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <vector>
#include <unordered_set>

typedef std::pair<std::string, std::string> k8s_pair_t;
typedef std::vector<k8s_pair_t>             k8s_pair_list;

class k8s_pod_t;
class k8s_service_t;

class k8s_container
{
public:
	typedef std::vector<k8s_container> list;

	class port
	{
	public:
		void set_name(const std::string& name);

		const std::string& get_name() const;

		void set_port(uint32_t port);

		uint32_t get_port() const;

		void set_protocol(const std::string& protocol);

		const std::string& get_protocol() const;

		bool operator==(const port& other) const;

		bool operator!=(const port& other) const;

	private:
		std::string m_name;
		uint32_t    m_port = 0;
		std::string m_protocol;
	};

	typedef std::vector<port> port_list;

	k8s_container();

	k8s_container(const std::string& name, const port_list& ports);

	k8s_container(const k8s_container& other);

	k8s_container(k8s_container&& other);

	k8s_container& operator=(const k8s_container& other);

	bool has_port(const std::string& port_name) const;

	const port* get_port(const std::string& port_name) const;

	void set_name(const std::string& name);

	const std::string& get_name() const;

	bool operator==(const k8s_container& other) const;

	bool operator!=(const k8s_container& other) const;

private:
	std::string m_name;
	port_list   m_ports;
};

// 
// component
//

class k8s_component
{
public:
	enum type
	{
		K8S_NODES,
		K8S_NAMESPACES,
		K8S_PODS,
		K8S_REPLICATIONCONTROLLERS,
		K8S_SERVICES,
		K8S_COMPONENT_COUNT
	};

	typedef std::pair<type, std::string> component_pair;
	typedef std::map<type, std::string> component_map;
	static const component_map list;

	k8s_component() = delete;

	k8s_component(const std::string& name, const std::string& uid, const std::string& ns = "");

	const std::string& get_name() const;

	void set_name(const std::string& name);

	const std::string& get_uid() const;

	void set_uid(const std::string& uid);

	const std::string& get_namespace() const;

	void set_namespace(const std::string& ns);

	k8s_pair_t* get_label(const k8s_pair_t& label);

	const k8s_pair_list& get_labels() const;

	void set_labels(k8s_pair_list&& labels);

	void add_labels(k8s_pair_list&& labels);

	void swap_labels(k8s_pair_list& new_labels);

	void push_label(const k8s_pair_t& label);

	void emplace_label(const k8s_pair_t& label);

	k8s_pair_t* get_selector(const k8s_pair_t& selector);

	const k8s_pair_list& get_selectors() const;

	void set_selectors(k8s_pair_list&& selectors);

	void add_selectors(k8s_pair_list&& selectors);

	void swap_selectors(k8s_pair_list& new_selectors);

	void push_selector(const k8s_pair_t& selector);

	void emplace_selector(k8s_pair_t&& selector);

	// extracts labels or selectors
	static k8s_pair_list extract_object(const Json::Value& object, const std::string& name);

	static std::vector<std::string> extract_pod_container_ids(const Json::Value& item);

	static size_t extract_pod_restart_count(const Json::Value& item);

	static k8s_container::list extract_pod_containers(const Json::Value& item);

	static void extract_pod_data(const Json::Value& item, k8s_pod_t& pod);

	static void extract_services_data(const Json::Value& spec, k8s_service_t& service, const std::vector<k8s_pod_t>& pods);

	static const std::string& get_name(const component_pair& p);

	static std::string get_name(type t);

	static type get_type(const component_pair& p);

	static type get_type(const std::string& name);

	bool selector_in_labels(const k8s_pair_t& selector, const k8s_pair_list& labels) const;

	bool selectors_in_labels(const k8s_pair_list& labels) const;

private:
	std::string   m_name;
	std::string   m_uid;
	std::string   m_ns;
	k8s_pair_list m_labels;
	k8s_pair_list m_selectors;

	friend class k8s_state_t;
};


//
// namespace
//

class k8s_ns_t : public k8s_component
{
public:
	k8s_ns_t(const std::string& name, const std::string& uid, const std::string& ns = "");
};


//
// node
//

class k8s_node_t : public k8s_component
{
public:
	typedef std::unordered_set<std::string> host_ip_list;

	k8s_node_t(const std::string& name, const std::string& uid, const std::string& ns = "");

	const host_ip_list& get_host_ips() const;

	void set_host_ips(host_ip_list&& host_ips);

	void add_host_ips(host_ip_list&& host_ips);

	void emplace_host_ip(std::string&& host_ip);

	static host_ip_list extract_addresses(const Json::Value& status);

private:
	host_ip_list m_host_ips;
};


//
// pod
//

class k8s_pod_t : public k8s_component
{
public:
	typedef std::vector<std::string> container_id_list;
	typedef k8s_container::list container_list;

	k8s_pod_t(const std::string& name, const std::string& uid, const std::string& ns = "");

	// container IDs
	const container_id_list& get_container_ids() const;
	void set_container_ids(container_id_list&& container_ids);
	void add_container_ids(container_id_list&& container_ids);
	void push_container_id(const std::string& container_id);
	void emplace_container_id(std::string&& container_id);

	// restart count
	size_t get_restart_count() const;
	void set_restart_count(size_t rc);

	// containers
	const container_list& get_containers() const;
	void set_containers(container_list&& containers);
	void add_containers(container_list&& containers);
	void push_container(const k8s_container& container);
	void emplace_container(k8s_container&& container);
	std::string* get_container_id(const std::string& container_id);
	k8s_container* get_container(const std::string& container_name);

	// node name, host IP and internal IP
	const std::string& get_node_name() const;
	void set_node_name(const std::string& name);
	const std::string& get_host_ip() const;
	void set_host_ip(const std::string& host_ip);
	const std::string& get_internal_ip() const;
	void set_internal_ip(const std::string& internal_ip);

	// comparison
	bool operator==(const k8s_pod_t& other) const;
	bool operator!=(const k8s_pod_t& other) const;
	bool has_container_id(const std::string& container_id);

private:
	container_id_list m_container_ids;
	container_list    m_containers;
	std::string       m_node_name;
	std::string       m_host_ip;
	std::string       m_internal_ip;
	size_t            m_restart_count;
};


//
// replication controller
//

class k8s_rc_t : public k8s_component
{
public:
	static const int UNKNOWN_REPLICAS = -1;
	k8s_rc_t(const std::string& name, const std::string& uid, const std::string& ns = "");

	std::vector<const k8s_pod_t*> get_selected_pods(const std::vector<k8s_pod_t>& pods) const;

	void set_spec_replicas(int replicas);
	int get_spec_replicas() const;
	void set_stat_replicas(int replicas);
	int get_stat_replicas() const;
	void set_replicas(const Json::Value& item);

private:
	int get_replica(const Json::Value& item);

	int m_spec_replicas = UNKNOWN_REPLICAS;
	int m_stat_replicas = UNKNOWN_REPLICAS;
};


//
// service
//

class k8s_service_t : public k8s_component
{
public:
	struct net_port
	{
		uint32_t    m_port = 0;
		std::string m_protocol;
		uint32_t    m_target_port = 0;
		uint32_t    m_node_port = 0;
	};

	typedef std::vector<net_port> port_list;

	k8s_service_t(const std::string& name, const std::string& uid, const std::string& ns = "");

	const std::string& get_cluster_ip() const;

	void set_cluster_ip(const std::string& cluster_ip);

	const port_list& get_port_list() const;

	void set_port_list(port_list&& ports);

	std::vector<const k8s_pod_t*> get_selected_pods(const std::vector<k8s_pod_t>& pods) const;

private:
	std::string m_cluster_ip;
	port_list   m_ports;
};

typedef std::vector<k8s_ns_t>      k8s_namespaces;
typedef std::vector<k8s_node_t>    k8s_nodes;
typedef std::vector<k8s_pod_t>     k8s_pods;
typedef std::vector<k8s_rc_t>      k8s_controllers;
typedef std::vector<k8s_service_t> k8s_services;

//
// container
//

inline const std::string& k8s_container::get_name() const
{
	return m_name;
}

inline void k8s_container::set_name(const std::string& name)
{
	m_name = name;
}

inline bool k8s_container::operator==(const k8s_container& other) const
{
	if(&other == this) { return true; }
	return (other.m_name == m_name) && (other.m_ports == m_ports);
}

inline bool k8s_container::operator!=(const k8s_container& other) const
{
	if(&other == this) { return false; }
	return !(other == *this);
}

//
// container::port
//

inline void k8s_container::port::set_name(const std::string& name)
{
	m_name = name;
}

inline const std::string& k8s_container::port::get_name() const
{
	return m_name;
}

inline void k8s_container::port::set_port(uint32_t port)
{
	m_port = port;
}

inline uint32_t k8s_container::port::get_port() const
{
	return m_port;
}

inline void k8s_container::port::set_protocol(const std::string& protocol)
{
	m_protocol = protocol;
}

inline const std::string& k8s_container::port::get_protocol() const
{
	return m_protocol;
}

inline bool k8s_container::port::operator==(const port& other) const
{
	if(&other == this) { return true; }
	return other.m_name == m_name &&
			other.m_port == m_port &&
			other.m_protocol == m_protocol;
}

inline bool k8s_container::port::operator!=(const port& other) const
{
	if(&other == this) { return false; }
	return !(other == *this);
}


//
// component
//

inline const std::string& k8s_component::get_name() const
{
	return m_name;
}

inline void k8s_component::set_name(const std::string& name)
{
	m_name = name;
}

inline const std::string& k8s_component::get_uid() const{
	
	return m_uid;
}

inline void k8s_component::set_uid(const std::string& uid)
{
	m_uid = uid;
}

inline const std::string& k8s_component::get_namespace() const
{
	return m_ns;
}

inline void k8s_component::set_namespace(const std::string& ns)
{
	m_ns = ns;
}

inline const k8s_pair_list& k8s_component::get_labels() const
{
	return m_labels;
}

inline void k8s_component::set_labels(k8s_pair_list&& labels)
{
	m_labels = std::move(labels);
}

inline void k8s_component::swap_labels(k8s_pair_list& new_labels)
{
	m_labels.swap(new_labels);
}

inline void k8s_component::push_label(const k8s_pair_t& label)
{
	m_labels.push_back(label);
}

inline void k8s_component::emplace_label(const k8s_pair_t& label)
{
	m_labels.emplace_back(label);
}

inline const k8s_pair_list& k8s_component::get_selectors() const
{
	return m_selectors;
}

inline void k8s_component::set_selectors(k8s_pair_list&& selectors)
{
	m_selectors = std::move(selectors);
}

inline void k8s_component::swap_selectors(k8s_pair_list& new_selectors)
{
	m_selectors.swap(new_selectors);
}

inline void k8s_component::push_selector(const k8s_pair_t& selector)
{
	m_selectors.push_back(selector);
}

inline void k8s_component::emplace_selector(k8s_pair_t&& selector)
{
	m_selectors.emplace_back(std::move(selector));
}

inline const std::string& k8s_component::get_name(const component_pair& p)
{
	return p.second;
}

inline k8s_component::type k8s_component::get_type(const component_pair& p)
{
	return p.first;
}

//
// node
//

inline const k8s_node_t::host_ip_list& k8s_node_t::get_host_ips() const
{
	return m_host_ips;
}

inline void k8s_node_t::set_host_ips(host_ip_list&& host_ips)
{
	m_host_ips = std::move(host_ips);
}

inline void k8s_node_t::add_host_ips(host_ip_list&& host_ips)
{
	m_host_ips.insert(host_ips.begin(), host_ips.end());
}

inline void k8s_node_t::emplace_host_ip(std::string&& host_ip)
{
	m_host_ips.emplace(std::move(host_ip));
}


//
// pod 
//

// container IDs

inline const k8s_pod_t::container_id_list& k8s_pod_t::get_container_ids() const
{
	return m_container_ids;
}

inline void k8s_pod_t::set_container_ids(container_id_list&& container_ids)
{
	m_container_ids = std::move(container_ids);
}

inline void k8s_pod_t::add_container_ids(container_id_list&& container_ids)
{
	m_container_ids.insert(m_container_ids.end(), container_ids.begin(), container_ids.end());
}

inline void k8s_pod_t::push_container_id(const std::string& container_id)
{
	m_container_ids.push_back(container_id);
}

inline void k8s_pod_t::emplace_container_id(std::string&& container_id)
{
	m_container_ids.emplace_back(std::move(container_id));
}

// restart count

inline size_t k8s_pod_t::get_restart_count() const
{
	return m_restart_count;
}

inline void k8s_pod_t::set_restart_count(size_t rc)
{
	if(rc >= m_restart_count)
	{
		m_restart_count = rc - m_restart_count;
	}
	else
	{
		g_logger.log("Invalid K8S pod restart count received (" + std::to_string(rc) + "), resetting to zero.", sinsp_logger::SEV_ERROR);
		m_restart_count = 0;
	}
}

// comparison

inline bool k8s_pod_t::operator==(const k8s_pod_t& other) const
{
	if(&other == this) { return true; }
	return other.m_container_ids == m_container_ids &&
			other.m_containers == m_containers &&
			other.m_host_ip == m_host_ip &&
			other.m_internal_ip == m_internal_ip;
}

inline bool k8s_pod_t::operator!=(const k8s_pod_t& other) const
{
	if(&other == this) { return false; }
	return !(other == *this);
}

// containers

inline const k8s_pod_t::container_list& k8s_pod_t::get_containers() const
{
	return m_containers;
}

inline void k8s_pod_t::set_containers(container_list&& containers)
{
	m_containers = std::move(containers);
}

inline void k8s_pod_t::add_containers(container_list&& containers)
{
	m_containers.insert(m_containers.end(), containers.begin(), containers.end());
}

inline void k8s_pod_t::push_container(const k8s_container& container)
{
	m_containers.push_back(container);
}

inline void k8s_pod_t::emplace_container(k8s_container&& container)
{
	m_containers.emplace_back(std::move(container));
}

inline const std::string& k8s_pod_t::get_node_name() const
{
	return m_node_name;
}

inline void k8s_pod_t::set_node_name(const std::string& name)
{
	m_node_name = name;
}

inline const std::string& k8s_pod_t::get_host_ip() const
{
	return m_host_ip;
}

inline void k8s_pod_t::set_host_ip(const std::string& host_ip)
{
	m_host_ip = host_ip;
}

inline const std::string& k8s_pod_t::get_internal_ip() const
{
	return m_internal_ip;
}

inline void k8s_pod_t::set_internal_ip(const std::string& internal_ip)
{
	m_internal_ip = internal_ip;
}

//
// replication controller
//

inline void k8s_rc_t::set_spec_replicas(int replicas)
{
	m_spec_replicas = replicas;
}

inline int k8s_rc_t::get_spec_replicas() const
{
	return m_spec_replicas;
}

inline void k8s_rc_t::set_stat_replicas(int replicas)
{
	m_stat_replicas = replicas;
}

inline int k8s_rc_t::get_stat_replicas() const
{
	return m_stat_replicas;
}

inline void k8s_rc_t::set_replicas(const Json::Value& item)
{
	m_spec_replicas = get_replica(item["spec"]);
	m_stat_replicas = get_replica(item["status"]);
}

//
// service
//

inline const std::string& k8s_service_t::get_cluster_ip() const
{
	return m_cluster_ip;
}

inline void k8s_service_t::set_cluster_ip(const std::string& cluster_ip)
{
	m_cluster_ip = cluster_ip;
}

inline const k8s_service_t::port_list& k8s_service_t::get_port_list() const
{
	return m_ports;
}

inline void k8s_service_t::set_port_list(port_list&& ports)
{
	m_ports = std::move(ports);
}
