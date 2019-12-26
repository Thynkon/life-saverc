#include <stdio.h>
#include <string.h>

#include <unistd.h>

void msg(const char *m) {
	write(1, m, strlen(m));
}

void errmsg(const char *m) {
	if (m == NULL) {
		m = "Error: No error description provided.\n";
	}

	fprintf(stderr, "%s", m);
}
