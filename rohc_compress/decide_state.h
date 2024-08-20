#include "base.h"

void tcp_decide_state(struct rohc_comp_ctxt *const context);

void rohc_comp_change_state(struct rohc_comp_ctxt *const context,
                            const int new_state);

void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context);

uint64_t rohc_time_interval(const struct rohc_ts begin, const struct rohc_ts end);
