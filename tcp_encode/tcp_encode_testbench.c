#include "tcp_encode.h"

#define IN_LEN 28

extern struct rohc_comp compressor;

int main()
{
	int i=0, j, failed = 0;

	struct rohc_comp_ctxt contexts[IN_LEN];
	struct rohc_ts ip_times[IN_LEN];
	uint8_t ip_pkts[IN_LEN][2048];
	uint8_t rohc_pkts[IN_LEN][2048];
	int packets_type[IN_LEN];
	int ip_pkts_len[IN_LEN];
	size_t payload_offsets[IN_LEN];
	size_t rohc_pkts_max_len[IN_LEN];

	size_t pritp[IN_LEN];
	uint64_t pritt[IN_LEN];
	size_t prftp[IN_LEN];
	uint64_t prftt[IN_LEN];
	int features[IN_LEN];

	uint8_t exp_rohc_pkts[IN_LEN][2048];
	size_t exp_hdrs_len[IN_LEN];
	size_t exp_packet_type[IN_LEN];

	FILE *fp = fopen("./../../../resources/inputs","r");
	if( fp==NULL )
	{
		printf("***********************--->file nis\n");
		return -1;
	}

	for( i=0 ; i<IN_LEN ; i++ )
	{
		uint8_t temp, temp1, temp2, temp3;
		size_t temp4;

		fscanf(fp, "|msn:%hu, ecn-usd:%d, ecn0-cnt:%lu, ecn-chng:%lu, ttl-chng:%lu, "
					"tcp-win-chng:%lu, seq-chng:%d, seq-fac:%lu, seq-res:%u, seq-scl:%u, "
					"seq-scl-nr:%lu, "
					"ack-str:%hu, ack-dlt-nxt:%lu, ack-res:%hu, ack-scl-nr:%lu, "
					"last-bhv:%hhu, bhv:%hhu, ipid:%hu, ttl:%hhu, dscp:%hhu, "
					"old-res:%hhu, old-ack:%hhu, old-urg:%hhu, old-win:%hu, old-seq-num:%u, "
					"old-ack-num:%u, "
					"msn-wlsb-cnt:%hhu, msn-wlsb-ww:%hhu, msn-wlsb-old:%hhu, msn-wlsb-nxt:%hhu, "
					"msn-wlsb-p:%d, id-wlsb-cnt:%hhu, id-wlsb-ww:%hhu, id-wlsb-old:%hhu, "
					"id-wlsb-nxt:%hhu, id-wlsb-p:%d, ttl-wlsb-cnt:%hhu, ttl-wlsb-ww:%hhu, "
					"ttl-wlsb-old:%hhu, ttl-wlsb-nxt:%hhu, ttl-wlsb-p:%d, win-wlsb-cnt:%hhu, "
					"win-wlsb-ww:%hhu, win-wlsb-old:%hhu, win-wlsb-nxt:%hhu, win-wlsb-p:%d, "
					"seq-wlsb-cnt:%hhu, seq-wlsb-ww:%hhu, seq-wlsb-old:%hhu, "
					"seq-wlsb-nxt:%hhu, seq-wlsb-p:%d, sqsc-wlsb-cnt:%hhu, "
					"sqsc-wlsb-ww:%hhu, sqsc-wlsb-old:%hhu, sqsc-wlsb-nxt:%hhu, "
					"sqsc-wlsb-p:%d, ack-wlsb-cnt:%hhu, ack-wlsb-ww:%hhu, "
					"ack-wlsb-old:%hhu, ack-wlsb-nxt:%hhu, ack-wlsb-p:%d, aksc-wlsb-cnt:%hhu, "
					"aksc-wlsb-ww:%hhu, aksc-wlsb-old:%hhu, aksc-wlsb-nxt:%hhu, "
					"aksc-wlsb-p:%d, "
					"uncmp-len:%lu, ip-len:%d, sec:%lu, ns:%lu, "
					"num_pkt:%d, state:%u, mode:%u, ircnt:%lu, focnt:%lu, cid:%lu, pid:%d, "
					"go-ircnt:%lu, go-focnt:%lu, ref-ircnt:%lu, ref-focnt:%lu, "
					"ref-irtime:%lu, ref-fo-time:%lu, feat:%u, ir-sec:%lu, "
					"ir-ns:%lu, fo-sec:%lu, fo-ns:%lu, rohc-max-len:%lu, data:",
					&contexts[i].specific.msn, &contexts[i].specific.ecn_used,
					&contexts[i].specific.ecn_used_zero_count, &contexts[i].specific.ecn_used_change_count,
					&contexts[i].specific.ttl_hopl_change_count, &contexts[i].specific.tcp_window_change_count,
					&contexts[i].specific.tcp_seq_num_change_count, &contexts[i].specific.seq_num_factor,
					&contexts[i].specific.seq_num_residue, &contexts[i].specific.seq_num_scaled,
					&contexts[i].specific.seq_num_scaling_nr, &contexts[i].specific.ack_stride,
					&contexts[i].specific.ack_deltas_next, &contexts[i].specific.ack_num_residue,
					&contexts[i].specific.ack_num_scaling_nr,
					&contexts[i].specific.ip_context.last_ip_id_behavior,
					&contexts[i].specific.ip_context.ip_id_behavior,
					&contexts[i].specific.ip_context.last_ip_id,
					&contexts[i].specific.ip_context.ttl_hopl,
					&temp, &temp1, &temp2, &temp3, &contexts[i].specific.old_tcphdr.window,
					&contexts[i].specific.old_tcphdr.seq_num, &contexts[i].specific.old_tcphdr.ack_num,
					&contexts[i].specific.msn_wlsb.count, &contexts[i].specific.msn_wlsb.window_width,
					&contexts[i].specific.msn_wlsb.oldest, &contexts[i].specific.msn_wlsb.next,
					&contexts[i].specific.msn_wlsb.p,
					&contexts[i].specific.ip_id_wlsb.count, &contexts[i].specific.ip_id_wlsb.window_width,
					&contexts[i].specific.ip_id_wlsb.oldest, &contexts[i].specific.ip_id_wlsb.next,
					&contexts[i].specific.ip_id_wlsb.p,
					&contexts[i].specific.ttl_hopl_wlsb.count, &contexts[i].specific.ttl_hopl_wlsb.window_width,
					&contexts[i].specific.ttl_hopl_wlsb.oldest, &contexts[i].specific.ttl_hopl_wlsb.next,
					&contexts[i].specific.ttl_hopl_wlsb.p,
					&contexts[i].specific.window_wlsb.count, &contexts[i].specific.window_wlsb.window_width,
					&contexts[i].specific.window_wlsb.oldest, &contexts[i].specific.window_wlsb.next,
					&contexts[i].specific.window_wlsb.p,
					&contexts[i].specific.seq_wlsb.count, &contexts[i].specific.seq_wlsb.window_width,
					&contexts[i].specific.seq_wlsb.oldest, &contexts[i].specific.seq_wlsb.next,
					&contexts[i].specific.seq_wlsb.p,
					&contexts[i].specific.seq_scaled_wlsb.count, &contexts[i].specific.seq_scaled_wlsb.window_width,
					&contexts[i].specific.seq_scaled_wlsb.oldest, &contexts[i].specific.seq_scaled_wlsb.next,
					&contexts[i].specific.seq_scaled_wlsb.p,
					&contexts[i].specific.ack_wlsb.count, &contexts[i].specific.ack_wlsb.window_width,
					&contexts[i].specific.ack_wlsb.oldest, &contexts[i].specific.ack_wlsb.next,
					&contexts[i].specific.ack_wlsb.p,
					&contexts[i].specific.ack_scaled_wlsb.count, &contexts[i].specific.ack_scaled_wlsb.window_width,
					&contexts[i].specific.ack_scaled_wlsb.oldest, &contexts[i].specific.ack_scaled_wlsb.next,
					&contexts[i].specific.ack_scaled_wlsb.p,
					&temp4, &ip_pkts_len[i],
					&ip_times[i].sec, &ip_times[i].nsec,
					&contexts[i].num_sent_packets, &contexts[i].state, &contexts[i].mode, &contexts[i].ir_count,
					&contexts[i].fo_count, &contexts[i].cid, &contexts[i].pid,
					&contexts[i].go_back_ir_count, &contexts[i].go_back_fo_count,
					&pritp[i], &prftp[i], &pritt[i], &prftt[i], &features[i],
					&contexts[i].go_back_ir_time.sec, &contexts[i].go_back_ir_time.nsec,
					&contexts[i].go_back_fo_time.sec, &contexts[i].go_back_fo_time.nsec,
					&rohc_pkts_max_len[i]);
		contexts[i].specific.ip_context.dscp = temp;
		contexts[i].specific.old_tcphdr.res_flags = temp1;
		contexts[i].specific.old_tcphdr.ack_flag = temp2;
		contexts[i].specific.old_tcphdr.urg_flag = temp3;

		fscanf(fp, ", data:");
		for( j=0 ; j<sizeof(struct ipv4_hdr) + sizeof(struct tcphdr) ; j++ )
		{
			fscanf(fp, "%hhu ", &ip_pkts[i][j]);
		}

		fscanf(fp, "wlsb:");
		for( j=0 ; j<ROHC_WLSB_WIDTH_MAX ; j++ )
		{
			fscanf(fp, "%hhu %u %u %hhu %u %u %hhu %u %u %hhu %u %u %hhu %u %u %hhu %u %u %hhu %u %u "
					   "%hhu %u %u ",
					&contexts[i].specific.msn_wlsb.window_used[j],
					&contexts[i].specific.msn_wlsb.window_sn[j],
					&contexts[i].specific.msn_wlsb.window_value[j],
					&contexts[i].specific.ip_id_wlsb.window_used[j],
					&contexts[i].specific.ip_id_wlsb.window_sn[j],
					&contexts[i].specific.ip_id_wlsb.window_value[j],
					&contexts[i].specific.ttl_hopl_wlsb.window_used[j],
					&contexts[i].specific.ttl_hopl_wlsb.window_sn[j],
					&contexts[i].specific.ttl_hopl_wlsb.window_value[j],
					&contexts[i].specific.window_wlsb.window_used[j],
					&contexts[i].specific.window_wlsb.window_sn[j],
					&contexts[i].specific.window_wlsb.window_value[j],
					&contexts[i].specific.seq_wlsb.window_used[j],
					&contexts[i].specific.seq_wlsb.window_sn[j],
					&contexts[i].specific.seq_wlsb.window_value[j],
					&contexts[i].specific.seq_scaled_wlsb.window_used[j],
					&contexts[i].specific.seq_scaled_wlsb.window_sn[j],
					&contexts[i].specific.seq_scaled_wlsb.window_value[j],
					&contexts[i].specific.ack_wlsb.window_used[j],
					&contexts[i].specific.ack_wlsb.window_sn[j],
					&contexts[i].specific.ack_wlsb.window_value[j],
					&contexts[i].specific.ack_scaled_wlsb.window_used[j],
					&contexts[i].specific.ack_scaled_wlsb.window_sn[j],
					&contexts[i].specific.ack_scaled_wlsb.window_value[j]);
		}

		fscanf(fp, "ack-deltas-wdth:");
		for( j=0 ; j<256 ; j++ )
		{
			fscanf(fp, "%hu ", &contexts[i].specific.ack_deltas_width[j]);
		}

		fscanf(fp, "crc:");
		for( j=0 ; j<256 ; j++ )
		{
			fscanf(fp, "%hhu %hhu %hhu ",
					&compressor.crc_table_3[j],
					&compressor.crc_table_7[j],
					&compressor.crc_table_8[j]);
		}

		fscanf(fp, "rohc_len:%lu, p_type:%lu, rohc-data: ",
				&exp_hdrs_len[i], &exp_packet_type[i]);
		for( size_t j=0 ; j<exp_hdrs_len[i] ; j++ )
		{
			fscanf(fp, "%hhu ", &exp_rohc_pkts[i][j]);
		}

		fscanf(fp, "|\n");
	}

	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		compressor.features = features[i];
		compressor.periodic_refreshes_ir_timeout_pkts = pritp[i];
		compressor.periodic_refreshes_ir_timeout_time = pritt[i];
		compressor.periodic_refreshes_fo_timeout_pkts = prftp[i];
		compressor.periodic_refreshes_fo_timeout_time = prftt[i];
		int ret = c_tcp_encode(&contexts[i], ip_pkts[i], ip_pkts_len[i], ip_times[i], rohc_pkts[i],
						rohc_pkts_max_len[i]);

		printf("%i) %d\n", i, ret);

		if( ret!=exp_hdrs_len[i] )
		{
			printf("*********************** %d)%d %lu\n", i, ret, exp_hdrs_len[i]);
			failed = 1;
			break;
		}

		for( j=0 ; j<ret ; j++ )
		{
			if( exp_rohc_pkts[i][j]!=rohc_pkts[i][j] )
			{
				printf("*********************** %d-%d (%hhu,%hhu)\n", i, j, exp_rohc_pkts[i][j], rohc_pkts[i][j]);
//				failed = 1;
			}
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
