#include "rohc_compress_wrapper.h"

#define IN_LEN 40

int main()
{
	int i=0, j, failed = 0;

	uint16_t uncomp_time[IN_LEN];
	uint8_t uncomp_data[IN_LEN][2048];
	uint8_t rohc_packets[IN_LEN][2048];
	uint8_t exp_rohc_pkts[IN_LEN][2048];
	size_t uncomp_len[IN_LEN];
	int exp_frame_len[IN_LEN];

	FILE *fp = fopen("./../../../resources/inputs","r");
//	FILE *fp_out = fopen("./../../../resources/outputs","w");
//	FILE *fp = fopen("resources/inputs","r");
	if( fp==NULL /*|| fp_out==NULL*/ )
	{
		printf("***********************--->file nis\n");
		return -1;
	}

	for( i=0 ; i<IN_LEN ; i++ )
	{
		fscanf(fp, "len:%lu, sec:%lu, uncomp_data:", &uncomp_len[i], &uncomp_time);
		for( j=0 ; j<uncomp_len[i] ; j++)
		{
			fscanf(fp, "%hhu ", &uncomp_data[i][j]);
		}
		fscanf(fp, ", frame_len:%d, rohc_data:", &exp_frame_len[i]);
		for( j=0 ; j<exp_frame_len[i] ; j++)
		{
			fscanf(fp, "%hhu ", &exp_rohc_pkts[i][j]);
		}
		fscanf(fp, "|\n");
	}

	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		int ret = rohc_compress_wrapper4(uncomp_data[i], uncomp_time[i], uncomp_len[i], rohc_packets[i]);

		if( ret!=exp_frame_len[i] )
		{
			printf("*********************** %d)%d %d\n", i, ret, exp_frame_len[i]);
			failed = 1;
			break;
		}

//		for( j=0 ; j<exp_rohc_len[i] ; j++ )
//		{
//			if( exp_rohc_pkts[i][j]!=rohc_packets[i][j] )
//			{
//				printf("*********************** %d-%d (%hhu,%hhu)\n", i, j,
//						exp_rohc_pkts[i][j], rohc_packets[i][j]);
//				failed = 1;
//			}
//			fprintf(fp_out, "%c", rohc_packets[i][j]);
//		}
//		fprintf(fp_out, "\n");
	}
//	fclose(fp_out);

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
