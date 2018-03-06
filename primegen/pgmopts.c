#include <stdint.h>
#include <stdbool.h>
#include "pgmopts.h"

static struct pgmopts_t pgmopts_rw = {
	.threads = 16,
	.prime_bits = 8192,
	.prime_count = 100,
};
const struct pgmopts_t *pgmopts = &pgmopts_rw;

bool parse_opts(int argc, char **argv) {
	return true;
}

