#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <regex.h>

#include <getopt.h>
#include <string.h>

// contains allow() (to check if a file exists)
#include <unistd.h>

#include <libssh/libssh.h>

#include "life-saverc.h"
#include "error-format.h"
#include "compression.h"
#include "ssh-connection.h"

void usage(void) {
	char *help_msg = "Usage:\n"
		"-f, --file filename\tFile to backup\n"
		"-h, --help\t\tDisplay this message\n"
		"-j, --bzip2\t\tFilter the archive through bzip2\n"
		"-z, --gzip\t\tFilter the archive through gzip";

	errmsg(help_msg);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
	char *err_msg = NULL;
	char *filename = NULL;
	char *output_filename = NULL;
	int compression = 0;

	int verbose = 0;
	int option = 0;
	int option_index = 0;

	struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"file", required_argument, 0, 'f'},
		{"gzip", no_argument, 0, 'z'},
		{"bzip2", no_argument, 0, 'j'}
	};

	struct location *src = NULL;
	struct location *dest = NULL;

	// Program return status
	int status = 0;

	int str_len = 0;

	// Full path of compressed file that will be used to generate
	// the string representation of the source ssh location 
	char *local_path = NULL;

	// String representation of source location
	char *src_str = NULL;
	// String representation of destination location
	char *dest_str = NULL;

	// default compression algorithm set to bz2
	compression = 'j';

	while ((option = getopt_long(argc, argv, "hf:jo:z", long_options, &option_index)) != -1) {
		switch(option) {
		case 'h':
			usage();
			break;

		case 'f':
			filename = strdup(optarg);
			if (filename == NULL) {
				fprintf(stderr, "Failed to retrieve file to backup!\n");
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
				fprintf(stderr, "Failed to retrieve output filename!\n");
				status = EXIT_FAILURE;

				goto end;
			}
			break;

		case 'z':
			compression = option;
			break;

		default:
			break;
		}
	}

	if (filename == NULL) {
		fprintf(stderr, "Output filename is not set!\n");

		status = EXIT_FAILURE;
		goto end;
	}

	if (output_filename == NULL) {
		fprintf(stderr, "Output filename is not set!\n");

		status = EXIT_FAILURE;
		goto end;
	}

	// Check if file to backup exists
	if ((access(filename, F_OK)) == -1) {
		if (asprintf(&err_msg, "%s does not exist\n", filename) > 0) {
			errmsg(err_msg);

			status = EXIT_FAILURE;
			goto end;
		}
	}

	if (create(output_filename, compression, filename, verbose) < 0) {
		if (asprintf(&err_msg, "Failed to compress %s", filename) > 0) {
			errmsg(err_msg);

			status = EXIT_FAILURE;
			goto end;
		}
	}

	// Retrieve real path of file to use it on source ssh location
	local_path = realpath(output_filename, NULL);
	if (local_path == NULL) {
		perror("realpath");
		
		status = EXIT_FAILURE;
		goto end;
	}

	// Generate string representation of source location
	str_len = strlen(USERNAME) + 1 + strlen(HOST) + 1 + strlen(local_path) + 1;
	src_str = (char*) malloc(str_len);
	if (src_str == NULL) {
		status = EXIT_FAILURE;
		goto end;
	}
	snprintf(src_str, str_len, "%s@%s:%s", USERNAME, HOST, local_path);

	// Parse and create source location
    src = parse_location(src_str);
    if (src == NULL) {
		fprintf(stderr, "Failed to parse src location\n");

		status = EXIT_FAILURE;
		goto end;
    }

	// Generate string representation of destination location
	str_len = strlen(USERNAME) + 1 + strlen(HOST) + 1 + strlen(REMOTE_DIR) + 1;
	dest_str = (char*) malloc(str_len);
	if (dest_str == NULL) {
		status = EXIT_FAILURE;
		goto end;
	}
	snprintf(dest_str, str_len, "%s@%s:%s", USERNAME, REMOTE_HOST, REMOTE_DIR);

	// Parse and create destination location
    dest = parse_location(dest_str);
    if (dest == NULL) {
		fprintf(stderr, "Failed to parse dest location\n");

		status = EXIT_FAILURE;
		goto end;
    }

	// Open a connection to each location
	if (open_location(src, READ) < 0) {
		status = EXIT_FAILURE;
		goto end;
	}

	if (open_location(dest, WRITE) < 0) {
		status = EXIT_FAILURE;
		goto end;
	}

	if (do_copy(src, dest, 0) < 0) {
		status = EXIT_FAILURE;
		goto end;
	}

end:
	if (err_msg != NULL) {
		free(err_msg);
		err_msg = NULL;
	}

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
		output_filename = NULL;
	}

	if (src_str != NULL) {
		free(src_str);
		src_str = NULL;
	}

	if (dest_str != NULL) {
		free(dest_str);
		dest_str = NULL;
	}

	if (src != NULL) {
		if (src->session) {
			close_location(src);
		}
		location_free(src);
		src = NULL;
	}

	if (dest != NULL) {
		if (dest->session) {
			close_location(dest);
		}
		location_free(dest);
		dest = NULL;
	}

	return status;
}
