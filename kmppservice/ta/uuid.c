/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include "uuid/uuid.h"

static char const hexdigits_lower[16] = "0123456789abcdef";

static void _uuid_fmt(const uuid_t uuid, char *buf, char const *restrict fmt)
{
	char *p = buf;
	int i;

	for (i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10) {
			*p++ = '-';
		}
		size_t tmp = uuid[i];
		*p++ = fmt[tmp >> 4];
		*p++ = fmt[tmp & 15];
	}
	*p = '\0';
}

void uuid_unparse_lower(const uuid_t uu, char *out)
{
	_uuid_fmt(uu, out, hexdigits_lower);
}
