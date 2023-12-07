// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#define _GNU_SOURCE
#include <dirent.h>

int main(void)
{
	char buf[128];
	return (int)getdents64(0, buf, sizeof(buf));
}

#undef _GNU_SOURCE
