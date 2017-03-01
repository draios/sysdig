//
// stopwatch.h
//
// stopwatch utility
//

#pragma once

#include <chrono>

class sinsp_stopwatch
{
public:
	sinsp_stopwatch();

	void stop();
	void start();
	void reset();

	template<typename T>
	typename T::rep elapsed() const
	{
		return std::chrono::duration_cast<T>(m_stop - m_start).count();
	}

private:
	void record(std::chrono::high_resolution_clock::time_point& tp);

	std::chrono::high_resolution_clock::time_point m_start;
	std::chrono::high_resolution_clock::time_point m_stop;
};

inline void sinsp_stopwatch::sinsp_stopwatch::reset()
{
	m_start = std::chrono::high_resolution_clock::time_point::min();
	m_stop = m_start;
}

inline void sinsp_stopwatch::sinsp_stopwatch::start()
{
	record(m_start);
}

inline void sinsp_stopwatch::sinsp_stopwatch::stop()
{
	record(m_stop);
}

inline void sinsp_stopwatch::record(std::chrono::high_resolution_clock::time_point& tp)
{
	tp = std::chrono::high_resolution_clock::now();
}
