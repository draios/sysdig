/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
#pragma once
#include <string>

// This class allows the caller to output sysdig tracers to /dev/null.
// An enter event is written by the constructor, and an exit event is
// written when stop() or the destructor is called.

// Delayed tracers can be used for debugging perf sensitive code blocks.
// No enter event is written, and an exit is only written if the span duration
// exceeds the timeout value.
// *WARNING* using (c)sysdig for tracer analysis with delayed tracers is not
// supported. Simple features work like filtering by span.tags, but others
// like duration fail because we didn't write an enter event.
class tracer_emitter
{
public:
	static const uint64_t no_timeout = ~0ULL;

	// - tag: name of the span
	// - timeout_ns: log when a span takes longer than this threshold
	// - delay_enter: conditionally write tracers only when the elapsed
	//   time is >timeout_ns
	tracer_emitter(std::string tag,
		       uint64_t timeout_ns = no_timeout,
		       bool delay_enter = false);
	// Passing a parent tracer causes the child to inherit certain values:
	// - tag is appended to the parent's span name "parent_tag.tag"
	// - timeout_ns is the lower of the parent and the passed value
	// - delay_enter is OR'd with the parents value so all children of a
	//   delayed parent will also be delayed
	tracer_emitter(std::string tag,
		       const tracer_emitter &parent,
		       uint64_t timeout_ns = no_timeout,
		       bool delay_enter = false);
	~tracer_emitter();

	tracer_emitter() = delete;
	tracer_emitter(const tracer_emitter&) = delete;
	tracer_emitter& operator=(const tracer_emitter&) = delete;

	// stop() is only needed if you want the exit event before the instance
	// gets destructed, i.e. goes out of scope. stop() should be called
	// after child tracers have exited, otherwise behavior is undefined.
	uint64_t stop();
	static void set_enabled(bool enabled) { m_enabled = enabled; }

private:
	uint64_t do_stop();
	void write_tracer(bool enter, uint64_t elapsed_ns = 0);

	const std::string m_tag;
	const uint64_t m_start_ns = 0;
	const uint64_t m_timeout_ns = 0;
	const bool m_delay_enter = false;
	bool m_exit_done = false;
	static bool m_enabled;
};
