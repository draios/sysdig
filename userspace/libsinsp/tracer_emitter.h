#pragma once
#include <string>

// This class allows the caller to output sysdig tracers
// to /dev/null.
class tracer_emitter
{
public:
	static const uint64_t no_timeout = ~0ULL;

	tracer_emitter(std::string tag, uint64_t timeout_ns=no_timeout);
	tracer_emitter(std::string tag, const tracer_emitter &parent, uint64_t timeout_ns=no_timeout);
	~tracer_emitter();

	tracer_emitter() = delete;
	tracer_emitter(const tracer_emitter&) = delete;
	tracer_emitter& operator=(const tracer_emitter&) = delete;

	// Stop is only needed if you want the exit
	// event before the instance gets destructed,
	// i.e. goes out of scope
	uint64_t stop();
	static void set_enabled(bool enabled) { m_enabled = enabled; }

private:
	void start();
	void write_tracer(const bool enter);
	const std::string& tag() const { return m_tag; }
	uint64_t elapsed_time() const;

	const std::string m_tag;
	const uint64_t m_start_ns = 0;
	const uint64_t m_timeout_ns = 0;
	bool m_exit_written = false;
	static bool m_enabled;
};
