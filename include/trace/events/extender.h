/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM extender

#if !defined(_TRACE_EXTENDER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EXTENDER_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(list_manipulation,

	TP_PROTO(const char *el, struct window_struct *w),

	TP_ARGS(el, w),

	TP_STRUCT__entry(
		__string(el, el)
		__field(unsigned int, win_num)
		__field(void __iomem *, addr)
		__field(phys_addr_t, phys_addr)
	),

	TP_fast_assign(
		__assign_str(el, el);
		__entry->win_num = w->win_num;
		__entry->addr = w->addr;
		__entry->phys_addr = w->phys_addr;
	),

	TP_printk("%s: win%d: entry: VA %px -> PA %llx",
		  __get_str(el), __entry->win_num, __entry->addr, __entry->phys_addr)
);

DEFINE_EVENT(list_manipulation, list_allocated_to_free,

	TP_PROTO(const char *el, struct window_struct *w),

	TP_ARGS(el, w)
);

DEFINE_EVENT(list_manipulation, list_free_to_allocated,

	TP_PROTO(const char *el, struct window_struct *w),

	TP_ARGS(el, w)
);

#endif /* _TRACE_EXTENDER_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
