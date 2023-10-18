#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define MAX_IR_COUNT  3U
#define MAX_FO_COUNT  3U

typedef enum
{
	ROHC_COMP_FEATURE_NONE            = 0,
	ROHC_COMP_FEATURE_COMPAT_1_6_x    = (1 << 0),
	ROHC_COMP_FEATURE_NO_IP_CHECKSUMS = (1 << 2),
	ROHC_COMP_FEATURE_DUMP_PACKETS    = (1 << 3),
	ROHC_COMP_FEATURE_TIME_BASED_REFRESHES = (1 << 4),

} rohc_comp_features_t;

typedef enum
{
	ROHC_UNKNOWN_MODE = 0,
	ROHC_U_MODE = 1,
} rohc_mode_t;

typedef enum
{
	ROHC_COMP_STATE_UNKNOWN = 0,
	ROHC_COMP_STATE_IR = 1,
	ROHC_COMP_STATE_FO = 2,
	ROHC_COMP_STATE_SO = 3,

} rohc_comp_state_t;

struct rohc_ts
{
	uint64_t sec;   /**< The seconds part of the timestamp */
	uint64_t nsec;  /**< The nanoseconds part of the timestamp */
};

struct rohc_comp
{
	int features;
	size_t periodic_refreshes_ir_timeout_pkts;
	uint64_t periodic_refreshes_ir_timeout_time;
	size_t periodic_refreshes_fo_timeout_pkts;
	uint64_t periodic_refreshes_fo_timeout_time;
};

struct rohc_comp_ctxt
{
	struct rohc_comp compressor;
	int mode;
	int state;
	size_t ir_count;
	size_t fo_count;
	size_t so_count;
	size_t go_back_fo_count;
	struct rohc_ts go_back_fo_time;
	size_t go_back_ir_count;
	struct rohc_ts go_back_ir_time;
};

void tcp_decide_state(struct rohc_comp_ctxt *const context,
                             struct rohc_ts pkt_time);

void rohc_comp_change_state(struct rohc_comp_ctxt *const context,
                            const int new_state);

void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context,
                                        const struct rohc_ts pkt_time);

uint64_t rohc_time_interval(const struct rohc_ts begin, const struct rohc_ts end);
