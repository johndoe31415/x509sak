/*
	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
	Copyright (C) 2018-2020 Johannes Bauer

	This file is part of x509sak.

	x509sak is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; this program is ONLY licensed under
	version 3 of the License, later versions are explicitly excluded.

	x509sak is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with x509sak; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	Johannes Bauer <JohannesBauer@gmx.de>
*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "pgmopts.h"
#include "argparse.h"

static struct pgmopts_t pgmopts_rw = {
	.genmode = MODE_RANDOM,
	.threads = 8,
	.prime_bits = 2048,
	.prime_type = PRIMETYPE_2_MSB,
	.prime_count = 10,
};
const struct pgmopts_t *pgmopts = &pgmopts_rw;

static bool parse_callback(enum argparse_option_t option, const char *value, argparse_errmsg_callback_t errmsg_callback) {
	switch (option) {
		case ARG_MODE:
			if (!strcmp(value, "random")) {
				pgmopts_rw.genmode = MODE_RANDOM;
			} else if (!strcmp(value, "crt")) {
				pgmopts_rw.genmode = MODE_CRT;
			} else {
				return false;
			}
			break;

		case ARG_PRIME_TYPE:
			if (!strcmp(value, "2msb")) {
				pgmopts_rw.prime_type = PRIMETYPE_2_MSB;
			} else if (!strcmp(value, "3msb")) {
				pgmopts_rw.prime_type = PRIMETYPE_3_MSB;
			} else {
				return false;
			}
			break;

		case ARG_THREAD_CNT:
			pgmopts_rw.threads = atoi(value);
			if ((pgmopts_rw.threads < 1) || (pgmopts_rw.threads > 1024)) {
				errmsg_callback("Thread count must be in between 1 and 1024.");
				return false;
			}
			break;

		case ARG_BIT_LENGTH:
			pgmopts_rw.prime_bits = atoi(value);
			if (pgmopts_rw.prime_bits < 8) {
				errmsg_callback("Primes must be at least 8 bit.");
				return false;
			}
			break;

		case ARG_NUM_PRIMES:
			pgmopts_rw.prime_count = atoi(value);
			break;
	}
	return true;
}

void parse_opts(int argc, char **argv) {
	argparse_parse_or_quit(argc, argv, parse_callback, NULL);
}
