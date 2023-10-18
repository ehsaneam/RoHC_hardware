#include "decide_state.h"

void tcp_decide_state(struct rohc_comp_ctxt *const context,
                             struct rohc_ts pkt_time)
{
	const rohc_comp_state_t curr_state = context->state;
	rohc_comp_state_t next_state;

	if(curr_state == ROHC_COMP_STATE_IR)
	{
		if(context->ir_count < MAX_IR_COUNT)
		{
			next_state = ROHC_COMP_STATE_IR;
		}
		else
		{
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_FO)
	{
		if(context->fo_count < MAX_FO_COUNT)
		{
			next_state = ROHC_COMP_STATE_FO;
		}
		else
		{
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_SO)
	{
		/* do not change state */
		next_state = ROHC_COMP_STATE_SO;
	}
	else
	{
		return;
	}

	rohc_comp_change_state(context, next_state);

	/* periodic context refreshes (RFC6846, §5.2.1.2) */
	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_periodic_down_transition(context, pkt_time);
	}
}

void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context,
                                        const struct rohc_ts pkt_time)
{
	rohc_comp_state_t next_state;

	if(context->go_back_ir_count >=
	   context->compressor.periodic_refreshes_ir_timeout_pkts)
	{
		context->go_back_ir_count = 0;
		next_state = ROHC_COMP_STATE_IR;
	}
	else if((context->compressor.features & ROHC_COMP_FEATURE_TIME_BASED_REFRESHES) != 0 &&
	        rohc_time_interval(context->go_back_ir_time, pkt_time) >=
	        (context->compressor.periodic_refreshes_ir_timeout_time << 10) )
	{
		const uint64_t interval_since_ir_refresh =
			rohc_time_interval(context->go_back_ir_time, pkt_time);
		context->go_back_ir_count = 0;
		next_state = ROHC_COMP_STATE_IR;
	}
	else if(context->go_back_fo_count >=
	        context->compressor.periodic_refreshes_fo_timeout_pkts)
	{
		context->go_back_fo_count = 0;
		next_state = ROHC_COMP_STATE_FO;
	}
	else if((context->compressor.features & ROHC_COMP_FEATURE_TIME_BASED_REFRESHES) != 0 &&
	        rohc_time_interval(context->go_back_fo_time, pkt_time) >=
	        (context->compressor.periodic_refreshes_fo_timeout_time << 10) )
	{
		const uint64_t interval_since_fo_refresh =
			rohc_time_interval(context->go_back_fo_time, pkt_time);
		context->go_back_fo_count = 0;
		next_state = ROHC_COMP_STATE_FO;
	}
	else
	{
		next_state = context->state;
	}

	rohc_comp_change_state(context, next_state);

	if(context->state == ROHC_COMP_STATE_SO)
	{
		context->go_back_ir_count++;
		context->go_back_fo_count++;
	}
	else if(context->state == ROHC_COMP_STATE_FO)
	{
		context->go_back_ir_count++;
		context->go_back_fo_time = pkt_time;
	}
	else /* ROHC_COMP_STATE_IR */
	{
		context->go_back_fo_time = pkt_time;
		context->go_back_ir_time = pkt_time;
	}
}

void rohc_comp_change_state(struct rohc_comp_ctxt *const context,
                            const int new_state)
{
	if(new_state != context->state)
	{
		/* reset counters */
		context->ir_count = 0;
		context->fo_count = 0;
		context->so_count = 0;

		/* change state */
		context->state = new_state;
	}
}

uint64_t rohc_time_interval(const struct rohc_ts begin, const struct rohc_ts end)
{
	uint64_t interval;

	interval = end.sec - begin.sec; /* difference btw seconds */
	interval = interval << 30;      /* convert in nanoseconds */
	interval += end.nsec;           /* additional end nanoseconds */
	interval -= begin.nsec;         /* superfluous begin nanoseconds */
	interval = interval >> 10;      /* convert in microseconds */

	return interval;
}
