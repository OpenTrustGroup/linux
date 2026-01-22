// SPDX-License-Identifier: GPL-2.0-only

#ifndef _GUEST_PAGE_POOL_H_
#define _GUEST_PAGE_POOL_H_

#define USE_XA_VERIFY	0

#if USE_XA_VERIFY
#include <linux/xarray.h>
#endif

#define GUEST_POOL_STATS		0

#define CHUNK_PAGE_COUNT	(SZ_2M >> PAGE_SHIFT)

#if GUEST_POOL_STATS
void guest_pool_clear_stats(void);
#else
static inline void guest_pool_clear_stats(void) {}
#endif

int alloc_guest_page_batch(size_t size, void *pool_ctx, void *callback);
int free_guest_page_batch(void *pool_ctx, int nr_pages);

int guest_pool_init(void);
void guest_pool_destroy(void);
void guest_pool_init_post(void);

u32 shrink_get_free_pages_count(void);
u32 shrink_free_pages(u32 pages);

void drain_guest_pool(u32 *pfns, u32 count, u32 *actual_count, void *ctx);

struct page *alloc_guest_page(size_t size);
void release_guest_page(struct page *page);

#endif /* _GUEST_PAGE_POOL_H_ */

