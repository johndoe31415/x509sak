#ifndef __PGMOPTS_H__
#define __PGMOPTS_H__

struct pgmopts_t {
	unsigned int threads;
	unsigned int prime_bits;
	unsigned int prime_count;
};

extern const struct pgmopts_t *pgmopts;

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool parse_opts(int argc, char **argv);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
