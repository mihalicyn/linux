/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UIDGID_TYPES_H
#define _LINUX_UIDGID_TYPES_H

#include <linux/types.h>

typedef struct {
	union {
		u64 val;
		struct {
			uid_t uid_val;
			uid_t uns_id;
		};
	};
} kuid_t;

typedef struct {
	union {
		u64 val;
		struct {
			gid_t gid_val;
			gid_t uns_id;
		};
	};
} kgid_t;

#endif /* _LINUX_UIDGID_TYPES_H */
