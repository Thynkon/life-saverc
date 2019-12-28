#ifndef MATCH_REGEX_H
#define MATCH_REGEX_H

#include <stdlib.h>
#include <regex.h>

char *get_regerror (int errcode, regex_t *compiled);
int match_regex(regex_t *preg, const char *regex, char *string, regmatch_t **pmatch, size_t nmatch, int cflags);

#endif
