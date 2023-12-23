#include "uncomp_tcp.h"


#define IN_LEN 19

int main()
{
	int i=0, j, failed = 0;

	size_t remain_len;
	struct tcphdr tcp[IN_LEN];
	struct rohc_comp_ctxt contexts[IN_LEN];

	uint16_t ack_num_residue[IN_LEN], ack_stride[IN_LEN];
	uint32_t seq_num_scaled[IN_LEN], seq_num_residue[IN_LEN];
	bool tcp_ack_flag_changed[IN_LEN], tcp_urg_flag_present[IN_LEN], tcp_urg_flag_changed[IN_LEN],
		tcp_seq_num_changed[IN_LEN], tcp_ack_num_changed[IN_LEN];
	size_t tcp_window_changed[IN_LEN], nr_window_bits_16383[IN_LEN], payload_len[IN_LEN],
		tcp_window_change_count[IN_LEN], seq_num_scaling_nr[IN_LEN], ack_num_scaling_nr[IN_LEN],
		seq_num_factor[IN_LEN], ack_deltas_next[IN_LEN], ack_num_scaled[IN_LEN],
		nr_seq_scaled_bits[IN_LEN], nr_ack_bits_16383[IN_LEN], nr_ack_scaled_bits[IN_LEN];

	printf("-----------------------------------> flag1\n");
	FILE *fp = fopen("./../../../resources/inputs","r");
	if( fp==NULL )
	{
		printf("***********************--->file nis\n");
		return -1;
	}
	for( i=0 ; i<IN_LEN ; i++ )
	{
		uint8_t temp, temp2, temp3, temp4, temp5;

		fscanf(fp, "|seq_num:%u, ack_num:%u, ack_flag:%hhu, tcp->urg_flag:%hhu, tcp_win:%hu, "
				   "old_ack_flag:%hhu, old_urg_flag:%hhu, old_tcp_win:%hu, win_chng_cnt:%lu, "
				   "msn:%hu, len:%lu, num_sent_packets:%d, seq_fac:%lu, seq_res:%u, "
				   "old_ack_num:%u, ack_std:%hu, ack_next:%lu, ack_res:%hu, old_seq_num:%u, "
				   "seq_scal:%lu, seq_scaled:%u, ack_scal:%lu, ack_scaled:%u, "
				   "win_wlsb_w:%lu, win_wlsb_old:%lu, win_wlsb_nxt:%lu, win_wlsb_cnt:%lu, "
				   "seq_wlsb_p:%d, seq_wlsb_cnt:%lu, ack_wlsb_cnt:%lu, ack_sca_wlsb_p:%d, "
				   "ack_sca_wlsb_cnt:%lu, ",
					&tcp[i].seq_num, &tcp[i].ack_num, &temp, &temp2, &tcp[i].window, &temp3, &temp4,
					&contexts[i].specific.old_tcphdr.window,
					&contexts[i].specific.tcp_window_change_count, &contexts[i].specific.msn,
					&contexts[i].specific.tmp.payload_len, &contexts[i].num_sent_packets,
					&contexts[i].specific.seq_num_factor, &contexts[i].specific.seq_num_residue,
					&contexts[i].specific.old_tcphdr.ack_num, &contexts[i].specific.ack_stride,
					&contexts[i].specific.ack_deltas_next, &contexts[i].specific.ack_num_residue,
					&contexts[i].specific.old_tcphdr.seq_num, &contexts[i].specific.seq_num_scaling_nr,
					&contexts[i].specific.seq_num_scaled, &contexts[i].specific.ack_num_scaling_nr,
					&contexts[i].specific.ack_num_scaled, &contexts[i].specific.window_wlsb.window_width,
					&contexts[i].specific.window_wlsb.oldest, &contexts[i].specific.window_wlsb.next,
					&contexts[i].specific.window_wlsb.count, &contexts[i].specific.seq_scaled_wlsb.p,
					&contexts[i].specific.seq_scaled_wlsb.count, &contexts[i].specific.ack_wlsb.count,
					&contexts[i].specific.ack_scaled_wlsb.p, &contexts[i].specific.ack_scaled_wlsb.count);

		tcp[i].ack_flag = temp;
		tcp[i].urg_flag = temp2;
		contexts[i].specific.old_tcphdr.ack_flag = temp3;
		contexts[i].specific.old_tcphdr.urg_flag = temp4;

		for( int j=0 ; j<16 ; j++ )
		{
			fscanf(fp, "(%d,%u,%u)-(%d,%u)-(%d,%u)-(%d,%u)-(%hu)",
				&contexts[i].specific.window_wlsb.window_used[j],
				&contexts[i].specific.window_wlsb.window_sn[j],
				&contexts[i].specific.window_wlsb.window_value[j],
				&contexts[i].specific.seq_scaled_wlsb.window_used[j],
				&contexts[i].specific.seq_scaled_wlsb.window_value[j],
				&contexts[i].specific.ack_wlsb.window_used[j],
				&contexts[i].specific.ack_wlsb.window_value[j],
				&contexts[i].specific.ack_scaled_wlsb.window_used[j],
				&contexts[i].specific.ack_scaled_wlsb.window_value[j],
				&contexts[i].specific.ack_deltas_width[j]);
		}

		fscanf(fp, "ack_chg:%d, urg_prs:%d, urg_chg:%d, win_chg:%lu, win_bits:%lu, len:%lu, "
				"win_cnt:%lu, seq_sn:%lu, ack_sn:%lu, seq_scl:%u, seq_res:%u, "
				"seq_fac:%lu, ack_dnex:%lu, ack_scl:%u, ack_res:%hu, ack_str:%hu, "
				"seq_chg:%d, seq_bit:%lu, ack_chg:%d, ack_bit:%lu, ack_sca:%lu|\n",
			    &tcp_ack_flag_changed[i], &tcp_urg_flag_present[i], &tcp_urg_flag_changed[i],
				&tcp_window_changed[i], &nr_window_bits_16383[i], &payload_len[i],
				&tcp_window_change_count[i], &seq_num_scaling_nr[i], &ack_num_scaling_nr[i], &seq_num_scaled[i],
				&seq_num_residue[i], &seq_num_factor[i], &ack_deltas_next[i], &ack_num_scaled[i],
				&ack_num_residue[i], &ack_stride[i], &tcp_seq_num_changed[i], &nr_seq_scaled_bits[i],
				&tcp_ack_num_changed[i], &nr_ack_bits_16383[i], &nr_ack_scaled_bits[i]);
	}
	fclose(fp);
	printf("-----------------------------------> flag2\n");

	for( i=0 ; i<IN_LEN ; i++ )
	{
		bool ret_val = tcp_encode_uncomp_tcp_fields(&contexts[i], &tcp[i]);
		if( ret_val!=1 || ack_deltas_next[i]!=contexts[i].specific.ack_deltas_next ||
			ack_num_scaled[i]!=contexts[i].specific.ack_num_scaled ||
			ack_num_residue[i]!=contexts[i].specific.ack_num_residue ||
			ack_stride[i]!=contexts[i].specific.ack_stride ||
			tcp_seq_num_changed[i]!=contexts[i].specific.tmp.tcp_seq_num_changed ||
			nr_seq_scaled_bits[i]!=contexts[i].specific.tmp.nr_seq_scaled_bits )
		{
			printf("*********************** %d)\n", i);
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
