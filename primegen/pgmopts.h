#ifndef __PGMOPTS_H__
#define __PGMOPTS_H__

enum genmode_t {
	MODE_RANDOM,
	MODE_CRT,
};

struct pgmopts_t {
	enum genmode_t genmode;
	unsigned int threads;
	unsigned int prime_bits;
	unsigned int prime_count;
};

extern const struct pgmopts_t *pgmopts;

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void parse_opts(int argc, char **argv);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
