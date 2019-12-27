#include <stdio.h>
#include <stdlib.h>
#include <sys/syslog.h>
#include <syslog.h>

#include "verbose.h"

// Initialisation of global variables declared in "verbose.h"
int verbose = 0;
int log_level = 0;

void log_message(int facility_priority, char *message) {
    if (verbose == 0) {
        return;
	}

	FILE *stream = NULL;

	if (log_level >= facility_priority) {
		if (message != NULL) {
			if (log_level <= LOG_ERR) {
				stream = stderr;
			} else {
				stream = stdout;
			}

			syslog(facility_priority, "%s", message);
			fprintf(stream, "%s\n", message);
		}
	}
}
