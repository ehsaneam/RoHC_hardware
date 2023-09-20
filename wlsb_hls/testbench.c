///*
#include <stdio.h>
#include "wlsb_16b.h"

#define IN_LEN 81

int main()
{
	int i, j;
	int failed = 0;
	struct c_wlsb wlsb[IN_LEN];
	uint16_t value[IN_LEN];
	int p[IN_LEN];
	size_t result_expected[IN_LEN];

	size_t result[IN_LEN];

	size_t chert;
	uint32_t chert2;
	bool chert3;
	uint8_t chert4;

	FILE *fp;
	fp=fopen("/home/esi/Projects/rohc_hw/wlsb_hls/resources/inputs","r");
	if( fp==NULL )
	{
		printf("file nis");
		return -1;
	}
	for( i=0 ; i<IN_LEN ; i++ )
	{
		fscanf(fp, "|win_w:%lu, old:%lu, nxt:%lu, cnt:%lu, bit:%lu, p:%d| ",
				&chert, &chert4, &chert, &wlsb[i].count,
				&chert, &chert);
		for( j=0 ; j<ROHC_WLSB_WIDTH_MAX ; j++ )
		{
			fscanf(fp, "(%d,%u,%u)", &chert3, &chert2,
					&wlsb[i].window_value[j]);
		}
		fscanf(fp, " |val:%u, mink:%lu, p:%d, result:%lu|\n", &value[i], &chert, &p[i], &result_expected[i]);
	}
	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		result[i] = wlsb_get_minkp_16bits(&wlsb[i], value[i], p[i]);
		//printf("------------------------>>>>>> %d)%d:%d\n", i, result[i], result_expected[i]);
		if( result[i]!=result_expected[i] )
		{
			failed = 1;
			printf("***********************inja kharab shod %d)%d:%d\n", i, result[i], result_expected[i]);
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
//*/

/*
#include <stdio.h>
#include "wlsb_32b.h"

#define IN_LEN 61

int main()
{
	int i, j;
	int failed = 0;
	struct c_wlsb wlsb[IN_LEN];
	uint32_t value[IN_LEN];
	int p[IN_LEN];
	uint8_t result_expected[IN_LEN];

	uint8_t result[IN_LEN];

	size_t chert;
	uint32_t chert2;
	bool chert3;
	uint8_t chert4;

	FILE *fp;
	fp=fopen("/home/esi/Projects/rohc_hw/wlsb_hls/resources/inputs32","r");
	if( fp==NULL )
	{
		printf("32-file nis");
		return -1;
	}
	for( i=0 ; i<IN_LEN ; i++ )
	{
		fscanf(fp, "|win_w:%lu, old:%lu, nxt:%lu, cnt:%lu, bit:%lu, p:%d| ",
				&chert, &wlsb[i].oldest, &chert, &wlsb[i].count,
				&chert, &chert);
		for( j=0 ; j<ROHC_WLSB_WIDTH_MAX ; j++ )
		{
			fscanf(fp, "(%d,%u,%u)", &chert3, &chert2,
					&wlsb[i].window_value[j]);
		}
		fscanf(fp, " |val:%u, mink:%lu, p:%d, result:%lu|\n", &value[i], &chert, &p[i], &result_expected[i]);
	}
	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		result[i] = wlsb_get_minkp_32bits(&wlsb[i], value[i], p[i]);
		//printf("------------------------>>>>>> %d)%d:%d\n", i, result[i], result_expected[i]);
		if( result[i]!=result_expected[i] )
		{
			printf("***********************inja kharab shod %d)%d:%d\n", i, result[i], result_expected[i]);
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
*/
