// This header file is imported before stdio.h because
// it might define _GNU_SOUCE (gnu extensions)
#include "asprintf.h"

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <regex.h>

#include <getopt.h>
#include <string.h>

// contains allow() (to check if a file exists)
#include <unistd.h>
// contains basename()
#include <libgen.h>

#include <libssh/libssh.h>

// contains contains like LOG_ERR, LOG_INFO, etc...
#include <sys/syslog.h>
#include <syslog.h>

#include "lifesaverc.h"
#include "error-format.h"
#include "compression.h"
#include "ssh-connection.h"
#include "verbose.h"

#if !defined(PACKAGE_VERSION) || !defined (PACKAGE_NAME)
#error PACKAGE_VERSION or PACKAGE_NAME missing!
#endif

void usage(void) {
	int rc = 0;
	char *help_msg = NULL;

	rc = asprintf(&help_msg,
		"usage: %s\n"
		"-d, --destination\tTarget host\n"
		"-f, --file filename\tFile to backup\n"
		"-h, --help\t\tDisplay this message\n"
		"-j, --bzip2\t\tFilter archive through bzip2\n"
		"-o, --output\t\tName of the compressed file\n"
		"-q, --quiet\t\tDon't send any log messages\n"
		"-v, --verbosity\t\tIncrement the log level of messages\n"
		"-V, --version\t\t%s version\n"
		"-z, --gzip\t\tFilter archive through gzip",
		PACKAGE_NAME, PACKAGE_NAME
	);

	if (rc > 0) {
		log_message(LOG_ERR, help_msg);
		exit(EXIT_FAILURE);

		free(help_msg);
		help_msg = NULL;
	}
}

int main(int argc, char **argv) {
	char *message = NULL;
	char *filename = NULL;
	char *output_filename = NULL;
	int compression = 0;

	int option = 0;
	int option_index = 0;

	struct option long_options[] = {
		{"destination",	required_argument,	0, 'd'},
		{"file",		required_argument,	0, 'f'},
		{"help",		no_argument,		0, 'h'},
		{"bzip2",		no_argument,		0, 'j'},
		{"output",		required_argument,	0, 'o'},
		{"quiet",		no_argument,		0, 'q'},
		{"verbosity", 	no_argument,		0, 'v'},
		{"version", 	no_argument,		0, 'V'},
		{"gzip",		no_argument,		0, 'z'}
	};

	struct location *src = NULL;
	struct location *dest = NULL;

	// Program return status
	int status = 0;

	// Full path of compressed file that will be used to generate
	// the string representation of the source ssh location 
	char *local_path = NULL;

	// String representation of source location
	char *src_str = NULL;
	// Basename of local file that will be used in log messages
	char *src_basename = NULL;

	// String representation of destination location
	char *dest_str = NULL;

	// Set default verbose mode 
	verbose = 1;
	// Set default log level(facility_priority)
	log_level = LOG_ERR;

	// default compression algorithm set to bz2
	compression = 'j';

	// Start connection with rsyslog server
	openlog(PACKAGE_NAME, LOG_CONS | LOG_PID, LOG_USER);

	while ((option = getopt_long(argc, argv, "d:f:hjo:qvVz", long_options, &option_index)) != -1) {
		switch(option) {
		case 'd':
			dest_str = strdup(optarg);
			if (dest_str == NULL) {
				status = EXIT_FAILURE;

				goto end;
			}
			break;

		case 'h':
			usage();
			break;

		case 'f':
			filename = strdup(optarg);
			if (filename == NULL) {
				status = EXIT_FAILURE;

				goto end;
			}
			break;

		case 'j':
			compression = option;
			break;

		case 'o':
			output_filename = strdup(optarg);
			if (output_filename == NULL) {
				status = EXIT_FAILURE;

				goto end;
			}
			break;

		case 'q':
			// This is a global variable defined in "verbose.h"
			verbose = 0;
			ssh_log_level = SSH_LOG_NONE;
			break;

		case 'v':
			log_level++;
			break;

		case 'V':
			if (asprintf(&message, "%s %s", PACKAGE_NAME, PACKAGE_VERSION) > 0) {
				log_message(LOG_ERR, message);

				free(message);
				message = NULL;
			}
		
			status = EXIT_SUCCESS;
			goto end;

		case 'z':
			compression = option;
			break;

		default:
			usage();
			break;
		}
	}

	if (compression == 'j') {
		log_message(LOG_INFO, "Compression algorithm set to bz2");
	} else {
		log_message(LOG_INFO, "Compression algorithm set to gzip");
	}

	if (filename == NULL) {
		log_message(LOG_ERR, "Name of file to be compressed is not set!");

		status = EXIT_FAILURE;
		goto end;
	}

	if (output_filename == NULL) {
		log_message(LOG_ERR, "Output filename is not set");

		status = EXIT_FAILURE;
		goto end;
	}

	// Check if file to backup exists
	if ((access(filename, F_OK)) == -1) {
		if (asprintf(&message, "%s does not exist\n", filename) > 0) {
			log_message(LOG_ERR, message);

			status = EXIT_FAILURE;
			goto end;
		}
	}

	if (dest_str == NULL) {
			log_message(LOG_ERR, "Destination location is not set");

			status = EXIT_FAILURE;
			goto end;
	}

	if (asprintf(&message, "Compressing %s", filename) > 0) {
		log_message(LOG_INFO, message);

		free(message);
		message = NULL;
	}

	if (create(output_filename, compression, filename) < 0) {
		if (asprintf(&message, "Failed to compress %s", filename) > 0) {
			log_message(LOG_ERR, message);

			status = EXIT_FAILURE;
			goto end;
		}
	} else {
		if (asprintf(&message, "%s compressed successfully", filename) > 0) {
			log_message(LOG_INFO, message);

			free(message);
			message = NULL;
		}
	}

	// Retrieve real path of file to use it on source ssh location
	local_path = realpath(output_filename, NULL);
	if (local_path == NULL) {
		if (asprintf(&message, "realpath failed: %s", strerror(errno)) > 0) {
			log_message(LOG_ERR, message);
		}
		
		status = EXIT_FAILURE;
		goto end;
	}

	// File to be send through ssh is the one has been compressed
	src_str = strdup(local_path);

	// Parse and create source location
    src = parse_location(src_str);
    if (src == NULL) {
		log_message(LOG_ERR, "Failed to parse source location");

		status = EXIT_FAILURE;
		goto end;
    } else {
		if (asprintf(&message, "%s successfully parsed", src_str) > 0) {
			log_message(LOG_INFO, message);

			free(message);
			message = NULL;
		}
	}

	// Dont check return value because basename() does not return error values
	src_basename = basename(src->path);

	// Parse and create destination location
    dest = parse_location(dest_str);
    if (dest == NULL) {
		if (asprintf(&message, "Failed to parse %s", dest_str) > 0) {
			log_message(LOG_ERR, message);
		}

		status = EXIT_FAILURE;
		goto end;
	} else {
		if (asprintf(&message, "%s successfully parsed", dest_str) > 0) {
			log_message(LOG_INFO, message);

			free(message);
			message = NULL;
		}
	}
	// Open a connection to each location
	if (open_location(src, READ) < 0) {
		if (asprintf(&message, "Failed to open %s", src_str) > 0) {
			log_message(LOG_ERR, message);
		}

		status = EXIT_FAILURE;
		goto end;
	} else {
		if (asprintf(&message, "%s successfully opened", src_str) > 0) {
			log_message(LOG_INFO, message);

			free(message);
			message = NULL;
		}
	}

	if (open_location(dest, WRITE) < 0) {
		if (asprintf(&message, "Failed to open %s", dest_str) > 0) {
			log_message(LOG_ERR, message);
		}

		status = EXIT_FAILURE;
		goto end;
	} else {
		if (asprintf(&message, "%s successfully opened", dest_str) > 0) {
			log_message(LOG_INFO, message);

			free(message);
			message = NULL;
		}
	}

	if (asprintf(&message, "Sending %s to through a ssh tunel", src_basename) > 0) {
		log_message(LOG_INFO, message);

		free(message);
		message = NULL;
	}

	if (do_copy(src, dest, 0) < 0) {
		if (asprintf(&message, "Failed to write %s into %s", src_str, dest_str) > 0) {
			log_message(LOG_ERR, message);
		}

		status = EXIT_FAILURE;
		goto end;
	} else {
		if (asprintf(&message, "%s successfully sent", src_basename) > 0) {
			log_message(LOG_INFO, message);

			free(message);
			message = NULL;
		}
	}

end:
	closelog();

	if (filename != NULL) {
		free(filename);
		filename = NULL;
	}

	if (output_filename != NULL) {
		free(output_filename);
		output_filename = NULL;
	}

	if (local_path != NULL) {
		free(local_path);
		local_path = NULL;
	}

	if (src != NULL) {
		if (src->session) {
			close_location(src);

			if (asprintf(&message, "%s closed", src_str) > 0) {
				log_message(LOG_INFO, message);

				free(message);
				message = NULL;
			}
		}
		location_free(src);
		src = NULL;
	}

	if (src_str != NULL) {
		free(src_str);
		src_str = NULL;
	}

	if (dest != NULL) {
		if (dest->session) {
			close_location(dest);

			if (asprintf(&message, "%s closed", dest_str) > 0) {
				log_message(LOG_INFO, message);

				free(message);
				message = NULL;
			}
		}
		location_free(dest);
		dest = NULL;
	}

	if (dest_str != NULL) {
		free(dest_str);
		dest_str = NULL;
	}

	if (message != NULL) {
		free(message);
		message = NULL;
	}

	return status;
}
