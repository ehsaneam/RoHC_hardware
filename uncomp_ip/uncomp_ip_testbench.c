#include "uncomp_ip.h"

#define IN_LEN 19

int main()
{
	int i, j, failed = 0;
	size_t remain_len;
	struct ipv4_hdr ip[IN_LEN];
	struct rohc_comp_ctxt contexts[IN_LEN];

	int exp_ttl_irg[IN_LEN];
	uint8_t exp_ttl_hopl[IN_LEN];
	uint16_t exp_ipid_delta[IN_LEN];
	bool exp_out_ttl_chng[IN_LEN], exp_tmp_bhv_chng[IN_LEN], exp_df_chng[IN_LEN], exp_dscp_chng[IN_LEN];
	bool exp_hopl_chng[IN_LEN];
	size_t exp_ipid3[IN_LEN], exp_ipid1[IN_LEN], exp_hopl_cnt[IN_LEN], exp_hopl_bits[IN_LEN];

	FILE *fp = fopen("./../../../resources/inputs","r");
	if( fp==NULL )
	{
		printf("***********************--->file nis\n");
		return -1;
	}
	for( i=0 ; i<IN_LEN ; i++ )
	{
		uint8_t temp, temp2, temp3;

		fscanf(fp, "|ip-cntx-ttl-hopl:%hhu, ip-cntx-behave:%hhu, ip-cntx-last-bahave:%hhu, "
			   "msn:%hu, ip-cntx-df:%hhu, ip-cntx-dscp:%hhu, ttl-hopl-chng-cnt:%lu"
			   "ipid-wlsb-win:%lu, ipid-wlsb-cnt:%lu, ipid-wlsb-old:%lu, "
			   "ipid-wlsb-next:%lu, ttl-wlsb-win:%lu, ttl-wlsb-cnt:%lu, "
			   "ttl-wlsb-old:%lu, ttl-wlsb-next:%lu, ttl-wlsb-p:%d, len:%lu, ipid-wlsb-data->",
			    &contexts[i].specific.ip_context.ttl_hopl, &contexts[i].specific.ip_context.ip_id_behavior,
				&contexts[i].specific.ip_context.last_ip_id_behavior, &contexts[i].specific.msn, &temp, &temp2,
				&contexts[i].specific.ttl_hopl_change_count, &contexts[i].specific.ip_id_wlsb.window_width,
				&contexts[i].specific.ip_id_wlsb.count, &contexts[i].specific.ip_id_wlsb.oldest,
				&contexts[i].specific.ip_id_wlsb.next, &contexts[i].specific.ttl_hopl_wlsb.window_width,
				&contexts[i].specific.ttl_hopl_wlsb.count, &contexts[i].specific.ttl_hopl_wlsb.oldest,
				&contexts[i].specific.ttl_hopl_wlsb.next, &contexts[i].specific.ttl_hopl_wlsb.p, &remain_len);

		contexts[i].specific.ip_context.df = temp;
		contexts[i].specific.ip_context.dscp = temp2;

		for( j=0 ; j<16 ; j++ )
		{
			fscanf(fp, "%u:%d, ", &contexts[i].specific.ip_id_wlsb.window_value[j],
					&contexts[i].specific.ip_id_wlsb.window_used[j]);
		}
		fscanf(fp, "ttl-wlsb-data->");
		for( j=0 ; j<16 ; j++ )
		{
			fscanf(fp, "%u:%d, ", &contexts[i].specific.ip_id_wlsb.window_value[j],
					&contexts[i].specific.ip_id_wlsb.window_used[j]);
		}

		fscanf(fp, "ver:%hhu, ipttl:%hhu, ip4id:%hu, ipdf:%hhu, ipdscp:%hhu, "
			   "ttl-irg:%d, out-ttl-chng:%d, tmp-bhv-chng:%d, tmp-ipid-delta:%hu, "
			   "tmp-ipid3:%lu, tmp-ipid1:%lu, tmp-df-chng:%d, tmp-dscp-chng:%d, "
			   "tmp-ttl-hopl:%hhu, tmp-ttl-chng:%d, tmp-ttl-cnt:%lu, tmp-ttl-bits:%lu, "
			   "retval:1|\n",
			    &temp, &ip[i].ttl, &ip[i].id, &temp2, &temp3, &exp_ttl_irg[i],
				&exp_out_ttl_chng[i], &exp_tmp_bhv_chng[i], &exp_ipid_delta[i], &exp_ipid3[i],
				&exp_ipid1[i], &exp_df_chng[i], &exp_dscp_chng[i], &exp_ttl_hopl[i],
				&exp_hopl_chng[i], &exp_hopl_cnt[i], &exp_hopl_bits[i]);
		ip[i].version = temp;
		ip[i].df = temp2;
		ip[i].dscp = temp3;
	}
	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		bool ret_val = tcp_encode_uncomp_ip_fields(&contexts[i], &ip[i]);
		if( ret_val!=1 )
		{
			printf("***********************ret kharab shod %d)%d:%d\n", i, 1, ret_val);
			failed = 1;
			break;
		}

		if( exp_ttl_irg[i]!=contexts[i].specific.tmp.ttl_irreg_chain_flag )
		{
			printf("***********************irg kharab shod %d)%d:%d\n", i, exp_ttl_irg[i],
					contexts[i].specific.tmp.ttl_irreg_chain_flag);
			failed = 1;
			break;
		}

		if( exp_out_ttl_chng[i]!=contexts[i].specific.tmp.outer_ip_ttl_changed )
		{
			printf("***********************out-ttl kharab shod %d)%d:%d\n", i, exp_out_ttl_chng[i],
					contexts[i].specific.tmp.outer_ip_ttl_changed);
			failed = 1;
			break;
		}

		if( exp_tmp_bhv_chng[i]!=contexts[i].specific.tmp.ip_id_behavior_changed )
		{
			printf("***********************bhv kharab shod %d)%d:%d\n", i, exp_tmp_bhv_chng[i],
					contexts[i].specific.tmp.ip_id_behavior_changed);
			failed = 1;
			break;
		}

		if( exp_ipid_delta[i]!=contexts[i].specific.tmp.ip_id_delta )
		{
			printf("***********************dlt kharab shod %d)%hu:%hu\n", i, exp_ipid_delta[i],
					contexts[i].specific.tmp.ip_id_delta);
			failed = 1;
			break;
		}

		if( exp_ipid3[i]!=contexts[i].specific.tmp.nr_ip_id_bits_3 )
		{
			printf("***********************ipid3 kharab shod %d)%lu:%lu\n", i, exp_ipid3[i],
					contexts[i].specific.tmp.nr_ip_id_bits_3);
			failed = 1;
			break;
		}

		if( exp_ipid1[i]!=contexts[i].specific.tmp.nr_ip_id_bits_1 )
		{
			printf("***********************ipid1 kharab shod %d)%lu:%lu\n", i, exp_ipid1[i],
					contexts[i].specific.tmp.nr_ip_id_bits_1);
			failed = 1;
			break;
		}

		if( exp_df_chng[i]!=contexts[i].specific.tmp.ip_df_changed )
		{
			printf("***********************dfcng kharab shod %d)%d:%d\n", i, exp_df_chng[i],
					contexts[i].specific.tmp.ip_df_changed);
			failed = 1;
			break;
		}

		if( exp_dscp_chng[i]!=contexts[i].specific.tmp.dscp_changed )
		{
			printf("***********************dscpcng kharab shod %d)%d:%d\n", i, exp_dscp_chng[i],
					contexts[i].specific.tmp.dscp_changed);
			failed = 1;
			break;
		}

		if( exp_ttl_hopl[i]!=contexts[i].specific.tmp.ttl_hopl )
		{
			printf("***********************ttl kharab shod %d)%hhu:%hhu\n", i, exp_ttl_hopl[i],
					contexts[i].specific.tmp.ttl_hopl);
			failed = 1;
			break;
		}

		if( exp_hopl_chng[i]!=contexts[i].specific.tmp.ttl_hopl_changed )
		{
			printf("***********************ttl-cng kharab shod %d)%d:%d\n", i, exp_hopl_chng[i],
					contexts[i].specific.tmp.ttl_hopl_changed);
			failed = 1;
			break;
		}

		if( exp_hopl_cnt[i]!=contexts[i].specific.ttl_hopl_change_count )
		{
			printf("***********************ttl-cnt kharab shod %d)%lu:%lu\n", i, exp_hopl_cnt[i],
					contexts[i].specific.ttl_hopl_change_count);
			failed = 1;
			break;
		}

		if( exp_hopl_bits[i]!=contexts[i].specific.tmp.nr_ttl_hopl_bits )
		{
			printf("***********************ttl-bit kharab shod %d)%lu:%lu\n", i, exp_hopl_bits[i],
					contexts[i].specific.tmp.nr_ttl_hopl_bits);
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
