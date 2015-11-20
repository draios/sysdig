//
// k8s_event_data.h
//
// connects and gets the data from k8s_net REST API interface
//
#pragma once

#include "k8s_component.h"


class k8s_event_data
{
public:
	k8s_event_data() = delete;

	k8s_event_data(k8s_component::type component, const char* data, int len);

	k8s_event_data(const k8s_event_data& other);

	k8s_event_data(k8s_event_data&& other);

	k8s_event_data& operator=(k8s_event_data&& other);

	k8s_component::type component() const;

	std::string data() const;

private:
	k8s_component::type m_component;
	std::string         m_data;
};

inline k8s_component::type k8s_event_data::component() const
{
	return m_component;
}
	
inline std::string k8s_event_data::data() const
{
	return m_data;
}