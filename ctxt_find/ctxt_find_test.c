#include "ctxt_find.h"

#define IN_LEN 40

int main()
{
	int i=0, j, failed = 0;

	int profile_id_hint[IN_LEN];
	struct rohc_ts arrival_time[IN_LEN];
	struct rohc_comp comp[IN_LEN];
	uint8_t data[IN_LEN][54];
	size_t cid_to_use[IN_LEN];

	FILE *fp = fopen("./../../../resources/inputs","r");
	if( fp==NULL )
	{
		printf("***********************--->file nis\n");
		return -1;
	}

	for( i=0 ; i<IN_LEN ; i++ )
	{
		fscanf(fp, "|pid_hint:%d, at_sec:%lu, at_ns:%lu, max_cid:%lu, usd_cntx:%lu, "
					"feat:%d, wlsb_win_wdth:%lu, ",
					&profile_id_hint[i], &arrival_time[i].sec, &arrival_time[i].nsec,
					&comp[i].medium.max_cid, &comp[i].num_contexts_used, &comp[i].features,
					&comp[i].wlsb_window_width);

		for( j=0 ; j<4 ; j++ )
		{
			fscanf(fp, "en:%d, ", &comp[i].enabled_profiles[j]);
		}

		for( j=0 ; j<comp[i].num_contexts_used ; j++)
		{
			fscanf(fp, "pid:%d, used:%d, src_prt:%hu, dst_prt:%hu, src_addr:%u, "
					"dst_addr:%u, proto:%hhu, lat_used:%lu, ",
				&comp[i].contexts[j].profile.id, &comp[i].contexts[j].used,
				&comp[i].contexts[j].specific.old_tcphdr.src_port,
				&comp[i].contexts[j].specific.old_tcphdr.dst_port,
				&comp[i].contexts[j].specific.ip_context.src_addr,
				&comp[i].contexts[j].specific.ip_context.dst_addr,
				&comp[i].contexts[j].specific.ip_context.protocol, &comp[i].contexts[j].latest_used);
		}
		fscanf(fp, "data:");
		for( j=0 ; j<54 ; j++ )
		{
			fscanf(fp, "%hhu ", &data[i][j]);
		}
		fscanf(fp, ", cid_to_use:%lu|\n", &cid_to_use[i]);
	}
	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		size_t ret = rohc_comp_find_ctxt(&comp[i], data[i], profile_id_hint[i], arrival_time[i]);
		if( ret!=cid_to_use[i] )
		{
			printf("%d)ret:%lu - exp:%lu\n", i, ret, cid_to_use[i]);
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
