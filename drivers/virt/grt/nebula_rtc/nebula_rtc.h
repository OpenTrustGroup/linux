/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NEBULA_RTC_H
#define _NEBULA_RTC_H

#include <linux/types.h>

void set_nebula_rtc(void);
void set_nebula_rtc2(uint64_t tv_nsec, int tz_min_west);
int get_nebula_rtc(uint64_t *tv_nsec, int *tz_min_west);

#endif /* _NEBULA_RTC_H */
