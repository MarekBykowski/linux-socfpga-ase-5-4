/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM extender

#if !defined(_TRACE_EXTENDER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EXTENDER_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(extender_list_manipulation,

	TP_PROTO(const char *el, struct window_struct *w),

	TP_ARGS(el, w),

	TP_STRUCT__entry(
		__string(el, el)
		__field(unsigned int, win_num)
		__field(void __iomem *, faulting_addr)
		__field(phys_addr_t, phys_addr)
	),

	TP_fast_assign(
		__assign_str(el, el);
		__entry->win_num = w->win_num;
		__entry->faulting_addr = w->faulting_addr;
		__entry->phys_addr = w->phys_addr;
	),

	TP_printk("%s: win%d: entry: VA %px -> PA %llx",
		  __get_str(el), __entry->win_num,
		  __entry->faulting_addr, __entry->phys_addr)
);

DEFINE_EVENT(extender_list_manipulation, extender_list_allocated_to_free,

	TP_PROTO(const char *el, struct window_struct *w),

	TP_ARGS(el, w)
);

DEFINE_EVENT(extender_list_manipulation, extender_list_free_to_allocated,

	TP_PROTO(const char *el, struct window_struct *w),

	TP_ARGS(el, w)
);

DECLARE_EVENT_CLASS(extender_fault_handler,

	TP_PROTO(const char *el, const char *some_string, unsigned long faulting_addr),

	TP_ARGS(el, some_string, faulting_addr),

	TP_STRUCT__entry(
		__string(el, el)
		__field(const char *, some_string)
		__field(unsigned long, faulting_addr)
	),

	TP_fast_assign(
		__assign_str(el, el);
		__entry->some_string = some_string;
		__entry->faulting_addr = faulting_addr;
	),

	TP_printk("(%s) %s %016lx",
		 __get_str(el), __entry->some_string, __entry->faulting_addr)
);

DEFINE_EVENT(extender_fault_handler, extender_fault_handler_entry,

	TP_PROTO(const char *el, const char *reason, unsigned long faulting_addr),

	TP_ARGS(el, reason, faulting_addr)
);

DEFINE_EVENT(extender_fault_handler, extender_fault_handler_exit,

	TP_PROTO(const char *el, const char *reason, unsigned long faulting_addr),

	TP_ARGS(el, reason, faulting_addr)
);

#endif /* _TRACE_EXTENDER_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
