#ifndef __ARGPARSE_H__
#define __ARGPARSE_H__

#include <stdbool.h>

enum argparse_option_t {
	ARG_MODE,
	ARG_THREAD_CNT,
	ARG_BIT_LENGTH,
	ARG_NUM_PRIMES,
};

typedef bool (*argparse_callback_t)(enum argparse_option_t option, const char *value);

bool argparse_parse(int argc, char **argv, argparse_callback_t argument_callback);
void argparse_show_syntax(void);
void argparse_parse_or_die(int argc, char **argv, argparse_callback_t argument_callback);

#endif
