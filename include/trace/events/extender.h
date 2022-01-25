/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM extender

#if !defined(_TRACE_EXTENDER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EXTENDER_H

#include <linux/tracepoint.h>

TRACE_EVENT(extender_log,

	TP_PROTO(unsigned int cpu, const char *reason),

	TP_ARGS(cpu, reason),

	TP_STRUCT__entry(
		__field(unsigned int, cpu)
		__field(const char *, reason)
	),

	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->reason = reason;
	),

	TP_printk("cpu=%u %s", __entry->cpu, __entry->reason)
);

#endif /* _TRACE_EXTENDER_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
