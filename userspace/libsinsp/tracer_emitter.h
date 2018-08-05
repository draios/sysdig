#pragma once
#include <string>

// This class allows the caller to output sysdig tracers
// to /dev/null.
class tracer_emitter
{
public:
	tracer_emitter(std::string tag);
	tracer_emitter(std::string tag, const tracer_emitter &parent);
	~tracer_emitter();

	tracer_emitter() = delete;
	tracer_emitter(const tracer_emitter&) = delete;
	tracer_emitter& operator=(const tracer_emitter&) = delete;

	// Stop is only needed if you want the exit
	// event before the instance gets destructed,
	// i.e. goes out of scope
	void stop();
	static void set_enabled(bool enabled) { m_enabled = enabled; }

private:
	void start();
	void write_tracer(const bool enter);
	const std::string& tag() const { return m_tag; }

	const std::string m_tag;
	bool m_exit_written = false;
	static bool m_enabled;
};
