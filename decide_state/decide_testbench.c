#include "decide_state.h"

#define IN_LEN 19

int main()
{
	int i, failed = 0;
	struct rohc_comp_ctxt contexts[IN_LEN];
	rohc_comp_state_t next_states[IN_LEN];
	struct rohc_ts pkt_times[IN_LEN];

	int exp_next_state[IN_LEN];
	size_t exp_back_ir_cnt[IN_LEN];
	size_t exp_back_fo_cnt[IN_LEN];
	struct rohc_ts exp_back_ir_time[IN_LEN];
	struct rohc_ts exp_back_fo_time[IN_LEN];

	FILE *fp;
	fp=fopen("./../../../resources/inputs","r");
	if( fp==NULL )
	{
		printf("***********************--->file nis\n");
		return -1;
	}
	for( i=0 ; i<IN_LEN ; i++ )
	{
		uint8_t temp;
		fscanf(fp, "|state:%d, ir_cnt:%lu, fo_cnt:%lu, mode:%d, sec:%lu, nsec:%lu, "
			   "back_ir_cnt:%lu, period_ir_pkt:%lu, feature:%d, back_ir_time:%lu.%lu, "
			   "period_ir_time:%lu, back_fo_cnt:%lu, back_fo_time:%lu.%lu, period_fo_cnt:%lu, "
			   "period_fo_time:%lu, next_state:%d, back_ir_cnt:%lu, back_fo_cnt:%lu, back_fo_time:%lu.%lu, "
			   "back_ir_time:%lu.%lu|\n",
				&contexts[i].state, &contexts[i].ir_count, &contexts[i].fo_count, &contexts[i].mode,
				&pkt_times[i].sec, &pkt_times[i].nsec, &contexts[i].go_back_ir_count,
				&contexts[i].compressor.periodic_refreshes_ir_timeout_pkts,
				&contexts[i].compressor.features, &contexts[i].go_back_ir_time.sec,
				&contexts[i].go_back_ir_time.nsec,
				&contexts[i].compressor.periodic_refreshes_ir_timeout_time,
				&contexts[i].go_back_fo_count, &contexts[i].go_back_fo_time.sec,
				&contexts[i].go_back_fo_time.nsec,
				&contexts[i].compressor.periodic_refreshes_fo_timeout_pkts,
				&contexts[i].compressor.periodic_refreshes_fo_timeout_time,
				&exp_next_state[i], &exp_back_ir_cnt[i], &exp_back_fo_cnt[i],
				&exp_back_fo_time[i].sec, &exp_back_fo_time[i].nsec,
				&exp_back_ir_time[i].sec, &exp_back_ir_time[i].nsec);
	}
	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		tcp_decide_state(&contexts[i], pkt_times[i]);
		if( exp_next_state[i]!=contexts[i].state )
		{
			printf("***********************next state kharab shod %d)%d:%d\n", i, exp_next_state[i], contexts[i].state);
			failed = 1;
			break;
		}
		if( exp_back_ir_cnt[i]!=contexts[i].go_back_ir_count )
		{
			printf("***********************ir cnt kharab shod %d)%lu:%lu\n", i, exp_back_ir_cnt[i], contexts[i].go_back_ir_count);
			failed = 1;
			break;
		}
		if( exp_back_fo_cnt[i]!=contexts[i].go_back_fo_count )
		{
			printf("***********************fo cnt kharab shod %d)%lu:%lu\n", i, exp_back_fo_cnt[i], contexts[i].go_back_fo_count);
			failed = 1;
			break;
		}
		if( exp_back_fo_time[i].sec!=contexts[i].go_back_fo_time.sec || exp_back_fo_time[i].nsec!=contexts[i].go_back_fo_time.nsec )
		{
			printf("***********************fo time kharab shod %d)%lu.%lu:%lu.%lu\n", i,
					exp_back_fo_time[i].sec, exp_back_fo_time[i].nsec, contexts[i].go_back_fo_time.sec, contexts[i].go_back_fo_time.nsec);
			failed = 1;
			break;
		}
		if( exp_back_ir_time[i].sec!=contexts[i].go_back_ir_time.sec || exp_back_ir_time[i].nsec!=contexts[i].go_back_ir_time.nsec)
		{
			printf("***********************ir time kharab shod %d)%lu.%lu:%lu.%lu\n", i,
					exp_back_ir_time[i].sec, exp_back_ir_time[i].nsec, contexts[i].go_back_ir_time.sec, contexts[i].go_back_ir_time.nsec);
			failed = 1;
			break;
		}
	}

	if( failed )
	{
		printf("***********************sag tush fail shod");
	}
	else
	{
		printf("***********************yes, ye karo doros anjam dadim");
	}
	return failed;
}
