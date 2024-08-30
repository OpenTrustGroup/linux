#undef TRACE_SYSTEM
#define TRACE_SYSTEM nebula_rproc

#if !defined(_TRACE_NEBULA_RPROC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_NEBULA_RPROC_H

#include <linux/tracepoint.h>

TRACE_EVENT(tracing_mark_write,
	TP_PROTO(int pid, const char *name, bool trace_begin),
	TP_ARGS(pid, name, trace_begin),
	TP_STRUCT__entry(
			__field(int, pid)
			__string(trace_name, name)
			__field(bool, trace_begin)
	),
	TP_fast_assign(
			__entry->pid = pid;
			__assign_str(trace_name, name);
			__entry->trace_begin = trace_begin;
	),
	TP_printk("%s|%d|%s", __entry->trace_begin ? "B" : "E",
		__entry->pid, __get_str(trace_name))
)

#define TRACE_FUNC_END() trace_tracing_mark_write(current->tgid, __func__, 0)
#define TRACE_FUNC_BEGIN() trace_tracing_mark_write(current->tgid, __func__, 1)
#define TRACE_END(name) trace_tracing_mark_write(current->tgid, name, 0)
#define TRACE_BEGIN(name) trace_tracing_mark_write(current->tgid, name, 1)

#endif /* _TRACE_NEBULA_RPROC_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>