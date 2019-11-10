#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <string.h>

// contains allow() (to check if a file exists)
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <archive.h>
#include <archive_entry.h>

#include <fcntl.h>

#include "life-saverc.h"

void usage(FILE *std) {
	char *help_msg = "%s usage\n\n"
		"-f, --file\tFile to backup\n"
		"-h, --help\tDisplay this message\n";

	fprintf(std, help_msg, PROGRAM_NAME);
}

// Based on: https://stackoverflow.com/a/309105
// Concatenate n strings
// Useful when we don't know neither the size of the strings nor the number of strings to concatenate
char *strmcat(char *header, const char **words) {
    size_t message_len = strlen(header) + 1; // + 1 for terminating NULL 
	size_t num_words = sizeof(words) / sizeof(char *);
    char *message = (char*) malloc(message_len);
    strncat(message, header, message_len);

    for(size_t i = 0; i < num_words; ++i) {
       message_len += strlen(words[i]);
       message = (char*) realloc(message, message_len);
       strncat(message, words[i], message_len);
    }

	return message;
}

int compress_file(const char *outname, const char *filename) {
	struct archive *archive;
	struct archive_entry *entry;
	struct stat st;
	char buff[8192];
	int len;
	int fd;

	fprintf(stdout, "Starting to archive %s\n", filename);

	archive = archive_write_new();
	archive_write_add_filter_gzip(archive);
	archive_write_set_format_pax_restricted(archive); // Note 1
	archive_write_open_filename(archive, outname);
//	while (filename) {
		stat(filename, &st);
		entry = archive_entry_new(); // Note 2
		archive_entry_set_pathname(entry, filename);
		archive_entry_set_size(entry, st.st_size); // Note 3
		archive_entry_set_filetype(entry, AE_IFREG);
		archive_entry_set_perm(entry, 0644);
		archive_write_header(archive, entry);
		fd = open(filename, O_RDONLY);
		len = read(fd, buff, sizeof(buff));

		while ( len > 0 ) {
			archive_write_data(archive, buff, len);
			len = read(fd, buff, sizeof(buff));
		}

		close(fd);
		archive_entry_free(entry);
		filename++;
//	}

	archive_write_close(archive); // Note 4
	archive_write_free(archive); // Note 5
	fprintf(stdout, "%s successfully archived\n", filename);

	return 0;
}

int main (int argc, char* argv[]) {
	int option = 0;
	int option_index = 0;

	// program's return value
	int status = 0;

	char *file_to_bak = NULL;
	const char *compressed_file_extension[] = {".tar.gz"};
	char *compressed_file_name = NULL;

	struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"file", required_argument, 0, 'f'}
	};

	while ((option = getopt_long(argc, argv, "hf:", long_options, &option_index)) != -1) {
		switch(option) {
		case 'h':
			usage(stdout);
			break;

		case 'f':
			if ((file_to_bak = strdup(optarg)) == NULL) {
				fprintf(stderr, "Failed to retrieve file to backup!");

				status = 1;
				goto END;
			}
			break;

		default:
			break;
		}
	}

	// Check if file to backup exists
	if ((access(file_to_bak, F_OK)) == -1) {
		fprintf(stderr, "%s does not exist\n", file_to_bak);
		
		status = 1;
		goto END;
	}

	compressed_file_name = strmcat(file_to_bak, compressed_file_extension);
	compress_file(compressed_file_name, file_to_bak);

	END:
	if (file_to_bak != NULL) {
		free(file_to_bak);
		file_to_bak = NULL;
	}

	if (compressed_file_name != NULL) {
		free(compressed_file_name);
		compressed_file_name = NULL;
	}

	return status;
}
