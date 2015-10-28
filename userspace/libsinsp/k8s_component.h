//
// k8s_component.h
//
// kubernetes components (nodes, namespaces, pods, replication controllers, services)
// abstraction
//

#pragma once

#include "json/json.h"
#include "sinsp.h"
#include <vector>
#include <map>
#include <unordered_map>

typedef std::pair<std::string, std::string> k8s_pair_s;
typedef std::vector<k8s_pair_s>             k8s_pair_list;

class k8s_pod_s;
class k8s_service_s;

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

	k8s_pair_s* get_label(const k8s_pair_s& label);

	const k8s_pair_list& get_labels() const;

	void set_labels(k8s_pair_list&& labels);

	void add_labels(k8s_pair_list&& labels);

	void swap_labels(k8s_pair_list& new_labels);

	void push_label(const k8s_pair_s& label);

	void emplace_label(const k8s_pair_s& label);

	k8s_pair_s* get_selector(const k8s_pair_s& selector);

	const k8s_pair_list& get_selectors() const;

	void set_selectors(k8s_pair_list&& selectors);

	void add_selectors(k8s_pair_list&& selectors);

	void swap_selectors(k8s_pair_list& new_selectors);

	void push_selector(const k8s_pair_s& selector);

	void emplace_selector(k8s_pair_s&& selector);

	static std::vector<std::string> extract_nodes_addresses(const Json::Value& status);

	// extracts labels or selectors
	static k8s_pair_list extract_object(const Json::Value& object, const std::string& name);

	static std::vector<std::string> extract_pod_container_ids(const Json::Value& item);

	static k8s_container::list extract_pod_containers(const Json::Value& item);

	static void extract_pod_data(const Json::Value& item, k8s_pod_s& pod);

	static void extract_services_data(const Json::Value& spec, k8s_service_s& service, const std::vector<k8s_pod_s>& pods);

	static const std::string& get_name(const component_pair& p);

	static std::string get_name(type t);

	static type get_type(const component_pair& p);

	static type get_type(const std::string& name);

private:
	std::string   m_name;
	std::string   m_uid;
	std::string   m_ns;
	k8s_pair_list m_labels;
	k8s_pair_list m_selectors;

	friend class k8s_state_s;
};


//
// namespace
//

class k8s_ns_s : public k8s_component
{
public:
	k8s_ns_s(const std::string& name, const std::string& uid, const std::string& ns = "");
};


//
// node
//

class k8s_node_s : public k8s_component
{
public:
	typedef std::vector<std::string> host_ip_list;

	k8s_node_s(const std::string& name, const std::string& uid, const std::string& ns = "");

	const host_ip_list& get_host_ips() const;

	void set_host_ips(host_ip_list&& host_ips);

	void add_host_ips(host_ip_list&& host_ips);

	void push_host_ip(const std::string& host_ip);

	void emplace_host_ip(std::string&& host_ip);

private:
	host_ip_list m_host_ips;
};


//
// pod
//

class k8s_pod_s : public k8s_component
{
public:
	typedef std::vector<std::string> container_id_list;
	typedef k8s_container::list container_list;

	k8s_pod_s(const std::string& name, const std::string& uid, const std::string& ns = "");

	// container IDs
	const container_id_list& get_container_ids() const;

	void set_container_ids(container_id_list&& container_ids);

	void add_container_ids(container_id_list&& container_ids);

	void push_container_id(const std::string& container_id);

	void emplace_container_id(std::string&& container_id);

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
	bool operator==(const k8s_pod_s& other) const;

	bool operator!=(const k8s_pod_s& other) const;

	bool has_container_id(const std::string& container_id);

private:
	container_id_list m_container_ids;
	container_list    m_containers;
	std::string       m_node_name;
	std::string       m_host_ip;
	std::string       m_internal_ip;
};


//
// replication controller
//

class k8s_rc_s : public k8s_component
{
public:
	k8s_rc_s(const std::string& name, const std::string& uid, const std::string& ns = "");
};


//
// service
//

class k8s_service_s : public k8s_component
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

	k8s_service_s(const std::string& name, const std::string& uid, const std::string& ns = "");

	const std::string& get_cluster_ip() const;

	void set_cluster_ip(const std::string& cluster_ip);

	const port_list& get_port_list() const;

	void set_port_list(port_list&& ports);

	bool selector_in_labels(const k8s_pair_list& labels, const k8s_pair_s& selector);

	const k8s_pod_s* get_selected_pod(const std::vector<k8s_pod_s>& pods);

private:
	std::string m_cluster_ip;
	port_list   m_ports;
};


//
// state
//

class k8s_state_s
{
public:

	typedef std::vector<k8s_ns_s>      namespaces;
	typedef std::vector<k8s_node_s>    nodes;
	typedef std::vector<k8s_pod_s>     pods;
	typedef std::vector<k8s_rc_s>      controllers;
	typedef std::vector<k8s_service_s> services;

	typedef std::unordered_map<std::string, k8s_pod_s*>     container_pod_map;
	typedef std::unordered_map<std::string, k8s_service_s*> pod_service_map;
	typedef std::unordered_map<std::string, k8s_rc_s*>      pod_rc_map;

	k8s_state_s();

	//
	// namespaces
	//

	const namespaces& get_namespaces() const;

	namespaces& get_namespaces();

	void push_namespace(const k8s_ns_s& ns);

	void emplace_namespace(k8s_ns_s&& ns);

	//
	// nodes
	//

	const nodes& get_nodes() const;

	nodes& get_nodes();

	k8s_node_s* get_node(const std::string& uid);

	void push_node(const k8s_node_s& node);

	void emplace_node(k8s_node_s&& node);

	//
	// pods
	//

	const pods& get_pods() const;

	pods& get_pods();

	void push_pod(const k8s_pod_s& pod);

	void emplace_pod(k8s_pod_s&& pod);

	void update_pod(k8s_pod_s& pod, const Json::Value& item, bool reset);

	bool has_pod(k8s_pod_s& pod);

	const k8s_pod_s::container_id_list& get_pod_container_ids(k8s_pod_s& pod);

	//
	// replication controllers
	//

	const controllers& get_rcs() const;

	controllers& get_rcs();

	void push_rc(const k8s_rc_s& rc);

	void emplace_rc(k8s_rc_s&& rc);

	//
	// services
	//

	const services& get_services() const;

	services& get_services();

	void push_service(const k8s_service_s& service);

	void emplace_service(k8s_service_s&& service);

	//
	// general
	//

	void replace_items(k8s_component::type t, const std::string& name, const std::vector<k8s_pair_s>&& items);

	k8s_component& add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns);
	
	void set_last_pod_node_name(const std::string& name);
	
	void set_last_pod_host_ip(const std::string& host_ip);
	
	void set_last_pod_internal_ip(const std::string& internal_ip);

	void add_last_node_ip(std::string&& ip);

	void add_last_pod_container_id(std::string&& container_id);

	// Returns true if component exists, false otherwise.
	template <typename C>
	bool has(const C& container, const std::string& uid) const
	{
		for (auto& comp : container)
		{
			if(uid == comp.get_uid())
			{
				return true;
			}
		}
		return false;
	}

	// Returns a pointer to existing component, if it exists.
	// If component does not exist, it returns null pointer.
	template <typename C, typename T>
	T* get_component(C& container, const std::string& uid)
	{
		for (auto& comp : container)
		{
			if(comp.get_uid() == uid)
			{
				return &comp;
			}
		}
		return 0;
	}

	// Returns the reference to existing component, if it exists.
	// If component does not exist, it emplaces it to the back of the
	// container and returns the reference of the added component.
	template <typename C, typename T>
	T& get_component(C& container, const std::string& name, const std::string& uid, const std::string& ns = "")
	{
		for (auto& comp : container)
		{
			if(comp.get_uid() == uid)
			{
				return comp;
			}
		}
		container.emplace_back(T(name, uid, ns));
		return container.back();
	}

	template <typename C>
	bool delete_component(C& components, const std::string& uid)
	{
		for (typename C::iterator component = components.begin(),
			end = components.end();
			component != end;
			++component)
		{
			if(component->get_uid() == uid)
			{
				components.erase(component);
				return true;
			}
		}

		return false;
	}

	//
	// cached lookup support
	//

	// pod by container;

	const k8s_pod_s* get_pod(const std::string& container)
	{
		container_pod_map::const_iterator it = m_container_pods.find(container);
		if(it != m_container_pods.end())
		{
			return it->second;
		}
		return 0;
	}

	bool is_pod_cached(const std::string& container_id)
	{
		return (m_container_pods.find(container_id) != m_container_pods.end());
	}

	void cache_pod(const std::string& container_id, k8s_pod_s& pod)
	{
		std::string::size_type pos = container_id.find(m_prefix);
		if (pos == 0)
		{
			m_container_pods[container_id.substr(m_prefix.size())] = &pod;
			return;
		}
		throw sinsp_exception("Invalid container ID (expected '" + m_prefix + "{ID}'): " + container_id);
	}

	void uncache_pod(const std::string& container_id)
	{
		container_pod_map::iterator it = m_container_pods.find(container_id);
		if(it != m_container_pods.end())
		{
			m_container_pods.erase(it);
		}
		throw sinsp_exception("Container not found: " + container_id);
	}

	// service by pod

	const k8s_service_s* get_service(const std::string& pod)
	{
		pod_service_map::const_iterator it = m_pod_services.find(pod);
		if(it != m_pod_services.end())
		{
			return it->second;
		}
		return 0;
	}

	// replication controller by pod

	const k8s_rc_s* get_rc(const std::string& pod)
	{
		pod_rc_map::const_iterator it = m_pod_rcs.find(pod);
		if(it != m_pod_rcs.end())
		{
			return it->second;
		}
		return 0;
	}

	void clear(k8s_component::type type = k8s_component::K8S_COMPONENT_COUNT);

private:
	namespaces  m_namespaces;
	nodes       m_nodes;
	pods        m_pods;
	controllers m_controllers;
	services    m_services;

	static const std::string m_prefix; // "docker://"
	container_pod_map        m_container_pods;
	pod_service_map          m_pod_services;
	pod_rc_map               m_pod_rcs;
};

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

inline void k8s_component::push_label(const k8s_pair_s& label)
{
	m_labels.push_back(label);
}

inline void k8s_component::emplace_label(const k8s_pair_s& label)
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

inline void k8s_component::push_selector(const k8s_pair_s& selector)
{
	m_selectors.push_back(selector);
}

inline void k8s_component::emplace_selector(k8s_pair_s&& selector)
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

inline const k8s_node_s::host_ip_list& k8s_node_s::get_host_ips() const
{
	return m_host_ips;
}

inline void k8s_node_s::set_host_ips(host_ip_list&& host_ips)
{
	m_host_ips = std::move(host_ips);
}

inline void k8s_node_s::add_host_ips(host_ip_list&& host_ips)
{
	m_host_ips.insert(m_host_ips.end(), host_ips.begin(), host_ips.end());
}

inline void k8s_node_s::push_host_ip(const std::string& host_ip)
{
	m_host_ips.push_back(host_ip);
}

inline void k8s_node_s::emplace_host_ip(std::string&& host_ip)
{
	m_host_ips.emplace_back(std::move(host_ip));
}


//
// pod 
//

// container IDs

inline const k8s_pod_s::container_id_list& k8s_pod_s::get_container_ids() const
{
	return m_container_ids;
}

inline void k8s_pod_s::set_container_ids(container_id_list&& container_ids)
{
	m_container_ids = std::move(container_ids);
}

inline void k8s_pod_s::add_container_ids(container_id_list&& container_ids)
{
	m_container_ids.insert(m_container_ids.end(), container_ids.begin(), container_ids.end());
}

inline void k8s_pod_s::push_container_id(const std::string& container_id)
{
	m_container_ids.push_back(container_id);
}

inline void k8s_pod_s::emplace_container_id(std::string&& container_id)
{
	m_container_ids.emplace_back(std::move(container_id));
}

// comparison

inline bool k8s_pod_s::operator==(const k8s_pod_s& other) const
{
	if(&other == this) { return true; }
	return other.m_container_ids == m_container_ids &&
			other.m_containers == m_containers &&
			other.m_host_ip == m_host_ip &&
			other.m_internal_ip == m_internal_ip;
}

inline bool k8s_pod_s::operator!=(const k8s_pod_s& other) const
{
	if(&other == this) { return false; }
	return !(other == *this);
}

// containers

inline const k8s_pod_s::container_list& k8s_pod_s::get_containers() const
{
	return m_containers;
}

inline void k8s_pod_s::set_containers(container_list&& containers)
{
	m_containers = std::move(containers);
}

inline void k8s_pod_s::add_containers(container_list&& containers)
{
	m_containers.insert(m_containers.end(), containers.begin(), containers.end());
}

inline void k8s_pod_s::push_container(const k8s_container& container)
{
	m_containers.push_back(container);
}

inline void k8s_pod_s::emplace_container(k8s_container&& container)
{
	m_containers.emplace_back(std::move(container));
}

inline const std::string& k8s_pod_s::get_node_name() const
{
	return m_node_name;
}

inline void k8s_pod_s::set_node_name(const std::string& name)
{
	m_node_name = name;
}

inline const std::string& k8s_pod_s::get_host_ip() const
{
	return m_host_ip;
}

inline void k8s_pod_s::set_host_ip(const std::string& host_ip)
{
	m_host_ip = host_ip;
}

inline const std::string& k8s_pod_s::get_internal_ip() const
{
	return m_internal_ip;
}

inline void k8s_pod_s::set_internal_ip(const std::string& internal_ip)
{
	m_internal_ip = internal_ip;
}


//
// service
//

inline const std::string& k8s_service_s::get_cluster_ip() const
{
	return m_cluster_ip;
}

inline void k8s_service_s::set_cluster_ip(const std::string& cluster_ip)
{
	m_cluster_ip = cluster_ip;
}

inline const k8s_service_s::port_list& k8s_service_s::get_port_list() const
{
	return m_ports;
}

inline void k8s_service_s::set_port_list(port_list&& ports)
{
	m_ports = std::move(ports);
}


//
// state
//

// namespaces
inline const k8s_state_s::namespaces& k8s_state_s::get_namespaces() const
{
	return m_namespaces;
}

inline k8s_state_s::namespaces& k8s_state_s::get_namespaces()
{
	return m_namespaces;
}

inline void k8s_state_s::push_namespace(const k8s_ns_s& ns)
{
	m_namespaces.push_back(ns);
}

inline void k8s_state_s::emplace_namespace(k8s_ns_s&& ns)
{
	m_namespaces.emplace_back(std::move(ns));
}

// nodes
inline const k8s_state_s::nodes& k8s_state_s::get_nodes() const
{
	return m_nodes;
}

inline k8s_state_s::nodes& k8s_state_s::get_nodes()
{
	return m_nodes;
}

inline void k8s_state_s::push_node(const k8s_node_s& node)
{
	m_nodes.push_back(node);
}

inline void k8s_state_s::emplace_node(k8s_node_s&& node)
{
	m_nodes.emplace_back(std::move(node));
}

// pods
inline const k8s_state_s::pods& k8s_state_s::get_pods() const
{
	return m_pods;
}

inline k8s_state_s::pods& k8s_state_s::get_pods()
{
	return m_pods;
}

inline void k8s_state_s::push_pod(const k8s_pod_s& pod)
{
	m_pods.push_back(pod);
}

inline void k8s_state_s::emplace_pod(k8s_pod_s&& pod)
{
	m_pods.emplace_back(std::move(pod));
}

inline const k8s_pod_s::container_id_list& k8s_state_s::get_pod_container_ids(k8s_pod_s& pod)
{
	return pod.get_container_ids();
}

// replication controllers
inline const k8s_state_s::controllers& k8s_state_s::get_rcs() const
{
	return m_controllers;
}

inline k8s_state_s::controllers& k8s_state_s::get_rcs()
{
	return m_controllers;
}

inline void k8s_state_s::push_rc(const k8s_rc_s& rc)
{
	m_controllers.push_back(rc);
}

inline void k8s_state_s::emplace_rc(k8s_rc_s&& rc)
{
	m_controllers.emplace_back(std::move(rc));
}

// services
inline const k8s_state_s::services& k8s_state_s::get_services() const
{
	return m_services;
}

inline k8s_state_s::services& k8s_state_s::get_services()
{
	return m_services;
}

inline void k8s_state_s::push_service(const k8s_service_s& service)
{
	m_services.push_back(service);
}

inline void k8s_state_s::emplace_service(k8s_service_s&& service)
{
	m_services.emplace_back(std::move(service));
}

// general
inline void k8s_state_s::set_last_pod_node_name(const std::string& name)
{
	m_pods.back().set_node_name(name);
}

inline void k8s_state_s::set_last_pod_host_ip(const std::string& host_ip)
{
	m_pods.back().set_host_ip(host_ip);
}

inline void k8s_state_s::set_last_pod_internal_ip(const std::string& internal_ip)
{
	m_pods.back().set_internal_ip(internal_ip);
}

inline void k8s_state_s::add_last_node_ip(std::string&& ip)
{
	m_nodes.back().emplace_host_ip(std::move(ip));
}

inline void k8s_state_s::add_last_pod_container_id(std::string&& container_id)
{
	m_pods.back().emplace_container_id(std::move(container_id));
}
