/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once
#ifdef GATHER_INTERNAL_STATS
#include <map>
#include <memory>
#include <string>

#define INTERNAL_COUNTER(X) internal_metrics::counter *X

namespace internal_metrics {

class metric;
class registry;
class counter;

class SINSP_PUBLIC metric_name
{
public:
	metric_name(std::string name, std::string description)
	{
		m_name = name;
		m_description = description;
	}

	bool operator<(const metric_name& other) const
	{
		return m_name<other.m_name;
	}

	std::string get_name() const
	{
		return m_name;
	}

	std::string get_description() const
	{
		return m_description;
	}

private:
	std::string m_name;
	std::string m_description;
};

class SINSP_PUBLIC processor
{
public:
	virtual void process(counter& metric) {};
};

class SINSP_PUBLIC metric
{
public:
	virtual ~metric() {}
	virtual void process(processor& metric_processor) = 0;
	virtual void clear() = 0;
};

class SINSP_PUBLIC registry
{
public:
	typedef std::map<metric_name,std::shared_ptr<counter>> metric_map_t;
	typedef metric_map_t::iterator metric_map_iterator_t;

	counter& register_counter(const metric_name& name)
	{
		std::shared_ptr<counter> p;
		p = std::make_shared<counter>();
    	m_metrics[name] = p;
		return *p.get();
	}

	metric_map_t& get_metrics()
	{
		return m_metrics;
	}

	void clear_all_metrics();

private:
	//template<typename T, typename... Args> T& create_metric(const metric_name& name, Args... args)
	//{
	//	if (m_metrics.find(name) == std::end(m_metrics))
	//	{
	//		m_metrics[name] = std::make_shared<T>(args...);
	//	}
	//	return dynamic_cast<T&>(*m_metrics[name]);
	//}

	metric_map_t m_metrics;

};


class SINSP_PUBLIC counter : public metric
{
public:
	~counter();
	counter();

	void increment()
	{
		m_value++;
	}

	void decrement()
	{
		m_value--;
	}

	void clear()
	{
		m_value = 0;
	}

	const uint64_t get_value()
	{
		return m_value;
	}

	void process(processor& metric_processor)
	{
		metric_processor.process(*this);
	}

private:

	uint64_t m_value;
};

}
#else
#define INTERNAL_COUNTER(X)
#endif // GATHER_INTERNAL_STATS
