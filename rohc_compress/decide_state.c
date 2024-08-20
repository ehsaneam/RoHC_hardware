#include "decide_state.h"

extern struct rohc_comp compressor;

void tcp_decide_state(struct rohc_comp_ctxt *const context)
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
		rohc_comp_periodic_down_transition(context);
	}
}

void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context)
{
	rohc_comp_state_t next_state;

	if(context->go_back_ir_count >= CHANGE_TO_IR_COUNT)
	{
		context->go_back_ir_count = 0;
		next_state = ROHC_COMP_STATE_IR;
	}
	else if(context->go_back_fo_count >= CHANGE_TO_FO_COUNT)
	{
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
