//
// k8s_net.cpp
//


#include "k8s_event_data.h"

k8s_event_data::k8s_event_data(k8s_component::type component, const char* data, int len):
	m_component(component),
	m_data(data, len)
{
}

k8s_event_data::k8s_event_data(const k8s_event_data& other):
	m_component(other.m_component),
	m_data(other.m_data)
{
}

k8s_event_data::k8s_event_data(k8s_event_data&& other):
	m_component(std::move(other.m_component)),
	m_data(std::move(other.m_data))
{
}

k8s_event_data& k8s_event_data::operator=(k8s_event_data&& other)
{
	if(this != &other)
	{
		m_component = other.m_component;
		m_data = other.m_data;
	}
	return *this;
}
