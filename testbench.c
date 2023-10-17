#include "change_detection.h"

#define IN_LEN 19

int main()
{
	int i, failed = 0;
	struct tcphdr tcps[IN_LEN];
	struct rohc_comp_ctxt contexts[IN_LEN];
	ipv4_context_t ip_contexts[IN_LEN];
	size_t outer_ip_size[IN_LEN];
	size_t uncomp_size[IN_LEN];
	uint8_t outer_ip_data[IN_LEN][200];

	uint16_t exp_r_msn[IN_LEN];
	size_t exp_r_tmp_len[IN_LEN];
	size_t exp_r_0_count[IN_LEN];
	size_t exp_r_chng_cnt[IN_LEN];
	uint8_t exp_r_behave[IN_LEN];
	bool exp_r_used[IN_LEN];
	bool exp_r_tmp_ecn[IN_LEN];

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
		fscanf(fp, "|cntx-sent:%d, tcp-cntx-msn:%hu, tcp-cntx-ecn-used:%d, "
				"tcp-cntx-ecn-cnt:%lu, tcp-cntx-ecn-chng:%lu, "
				"tcp-cntx-ip-cntx-last-id:%hu, uncomp-len:%lu, old:%hhu, uncomp-out-len:%lu, ",
				&contexts[i].num_sent_packets, &contexts[i].specific.msn, &contexts[i].specific.ecn_used,
				&contexts[i].specific.ecn_used_zero_count, &contexts[i].specific.ecn_used_change_count,
				&contexts[i].specific.ip_context.last_ip_id, &uncomp_size[i],
				&temp, &outer_ip_size[i]);
		contexts[i].specific.old_tcphdr.res_flags = temp;

		for( int j=0 ; j<outer_ip_size[i] ; j++)
		{
			fscanf(fp, "%hhu ", &outer_ip_data[i][j]);
		}
		fscanf(fp, ", tcp-cntx-msn:%hu, tcp-cntx-tmp-len:%lu, ip-behav:%hhu, tcp-cntx-tmp-ecn:%d,"
				" tcp-cntx-ecn-cnt:%lu, tcp-cntx-ecn-used:%d, tcp-cntx-ecn-chng:%lu|\n",
				&exp_r_msn[i], &exp_r_tmp_len[i], &exp_r_behave[i],
				&exp_r_tmp_ecn[i], &exp_r_0_count[i],
				&exp_r_used[i], &exp_r_chng_cnt[i]);
	}
	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *) outer_ip_data[i];
		struct tcphdr *tcp = (struct tcphdr *) (outer_ip_data[i] + sizeof(struct ipv4_hdr));

		tcp_detect_changes(&contexts[i], uncomp_size[i], ipv4_hdr, tcp);
		if( exp_r_msn[i]!=contexts[i].specific.msn )
		{
			printf("***********************msn kharab shod %d)%hu:%hu\n", i, exp_r_msn[i], contexts[i].specific.msn);
			failed = 1;
			break;
		}
		if( exp_r_tmp_len[i]!=contexts[i].specific.tmp.payload_len )
		{
			printf("***********************tmplen kharab shod %d)%lu:%lu\n", i, exp_r_tmp_len[i], contexts[i].specific.tmp.payload_len);
			failed = 1;
			break;
		}
		if( exp_r_behave[i]!=contexts[i].specific.ip_context.ip_id_behavior )
		{
			printf("***********************behave kharab shod %d)%hhu:%hhu\n", i,
					exp_r_behave[i], contexts[i].specific.ip_context.ip_id_behavior);
			failed = 1;
			break;
		}
		if( exp_r_tmp_ecn[i]!=contexts[i].specific.tmp.ecn_used_changed )
		{
			printf("***********************usdchg kharab shod %d)%d:%d\n", i, exp_r_tmp_ecn[i], contexts[i].specific.tmp.ecn_used_changed);
			failed = 1;
			break;
		}
		if( exp_r_0_count[i]!=contexts[i].specific.ecn_used_zero_count )
		{
			printf("***********************0cnt kharab shod %d)%lu:%lu\n", i, exp_r_0_count[i], contexts[i].specific.ecn_used_zero_count);
			failed = 1;
			break;
		}
		if( exp_r_used[i]!=contexts[i].specific.ecn_used )
		{
			printf("***********************ecnusd kharab shod %d)%d:%d\n", i, exp_r_used[i], contexts[i].specific.ecn_used);
			failed = 1;
			break;
		}
		if( exp_r_chng_cnt[i]!=contexts[i].specific.ecn_used_change_count )
		{
			printf("***********************cngcnt kharab shod %d)%lu:%lu\n", i, exp_r_chng_cnt[i], contexts[i].specific.ecn_used_change_count);
			failed = 1;
			break;
		}
	}

	if( failed )
	{
		printf("***********************32-sag tush fail shod");
	}
	else
	{
		printf("***********************32-yes, ye karo doros anjam dadim");
	}
	return failed;
}
