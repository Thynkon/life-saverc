#include <stdlib.h>
#include <regex.h>

#include "match-regex.h"

char *get_regerror (int errcode, regex_t *compiled) {
	size_t length = 0;
	char *buffer = NULL;

	length = regerror (errcode, compiled, NULL, 0);
	buffer = malloc(length);
	if (buffer == NULL) {
		return NULL;
	}

	(void) regerror (errcode, compiled, buffer, length);

	return buffer;
}

int match_regex(regex_t *preg, const char *regex, char *string, regmatch_t **pmatch, size_t nmatch, int cflags) {
	int retval = 0;

	retval = regcomp(preg, regex, cflags);
	if (retval != 0) {
		return retval;
	}

	retval = regexec(preg, string, nmatch, *pmatch, 0);
	if (retval != 0) {
		return retval;
	}

	return retval;
}
