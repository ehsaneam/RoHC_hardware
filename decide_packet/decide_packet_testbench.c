#include "decide_packet.h"

#define IN_LEN 19

int main()
{
	int i, failed = 0;
	struct rohc_comp_ctxt contexts[IN_LEN];
	struct tcphdr tcps[IN_LEN];
	ipv4_context_t ip_inner_contexts[IN_LEN];

	int exp_packet_type[IN_LEN];

	FILE *fp = fopen("./../../../resources/inputs","r");
	if( fp==NULL )
	{
		printf("***********************--->file nis\n");
		return -1;
	}
	printf("############--> %d\n", IN_LEN);
	for( i=0 ; i<IN_LEN ; i++ )
	{
		uint8_t temp, temp2;
		int temp3;

		fscanf(fp, "|state:%d, ir_cnt:%lu, fo_cnt:%lu, so_cnt:%lu, msn_bits:%lu,"
				   " rsf_flag:%hhu, out_ttl_chng:%d, behav_chng:%d, df_chng:%d, dscp_chng:%d,"
				   " ack_chng:%d, urg_prs:%d, urg_chng:%d, old_urg_ptr:%hu, urg_ptr:%hu,"
				   " ack_std:%hu, ack_scal:%lu, ecn_chng:%d, ttl_chng:%d, seq:%u, ack:%u,"
				   " behav:%hhu, ipid3:%lu, tll_num:%lu, win_chng:%lu, ack_bit:%lu,"
				   " win_bit:%lu, seq_chng:%d, ack_flg:%hhu, ack_num_chng:%d, seq_scal:%lu,"
				   " seq_scal_bit:%lu, ipid1:%lu, ack_scal_bit:%lu, len:%lu, packet_type:%d|\n",
					&tempo, &contexts[i].ir_count, &contexts[i].fo_count, &contexts[i].so_count,
					&contexts[i].specific.tmp.nr_msn_bits, &temp,
					&contexts[i].specific.tmp.outer_ip_ttl_changed,
					&contexts[i].specific.tmp.ip_id_behavior_changed, &contexts[i].specific.tmp.ip_df_changed,
					&contexts[i].specific.tmp.dscp_changed, &contexts[i].specific.tmp.tcp_ack_flag_changed,
					&contexts[i].specific.tmp.tcp_urg_flag_present,
					&contexts[i].specific.tmp.tcp_urg_flag_changed, &contexts[i].specific.old_tcphdr.urg_ptr,
					&tcps[i].urg_ptr, &contexts[i].specific.ack_stride, &contexts[i].specific.ack_num_scaling_nr,
					&contexts[i].specific.tmp.ecn_used_changed, &contexts[i].specific.tmp.ttl_hopl_changed,
					&tcps[i].seq_num, &tcps[i].ack_num,
					&ip_inner_contexts[i].ip_id_behavior,
					&contexts[i].specific.tmp.nr_ip_id_bits_3, &contexts[i].specific.tmp.nr_ttl_hopl_bits,
					&contexts[i].specific.tmp.tcp_window_changed, &contexts[i].specific.tmp.nr_ack_bits_16383,
					&contexts[i].specific.tmp.nr_window_bits_16383,
					&contexts[i].specific.tmp.tcp_seq_num_changed, &temp2,
					&contexts[i].specific.tmp.tcp_ack_num_changed, &contexts[i].specific.seq_num_scaling_nr,
					&contexts[i].specific.tmp.nr_seq_scaled_bits, &contexts[i].specific.tmp.nr_ip_id_bits_1,
					&contexts[i].specific.tmp.nr_ack_scaled_bits, &contexts[i].specific.tmp.payload_len,
					&exp_packet_type[i]);

		contexts[i].state = temp3;
		tcps[i].rsf_flags = temp;
		tcps[i].ack_flag = temp2;
	}
	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		rohc_packet_t p_type = tcp_decide_packet(&contexts[i], &ip_inner_contexts[i], &tcps[i]);
		if( exp_packet_type[i]!=p_type )
		{
			printf("***********************kharab shod %d)%d:%d\n", i, exp_packet_type[i], p_type);
			failed = 1;
			break;
		}
	}

	if( failed )
	{
		printf("***********************sag tush fail shod\n");
	}
	else
	{
		printf("***********************yes, ye karo doros anjam dadim\n");
	}
	return failed;
}
