#include "asprintf.h"

#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <archive.h>
#include <archive_entry.h>

#include <syslog.h>
#include <sys/syslog.h>

#include "error-format.h"
#include "verbose.h"

int create(char *filename, int compression, char *argv) {
	ssize_t len;
	int fd = 0;

	char buff[16384];
	char *message = NULL;

	struct archive *a = NULL;
	struct archive_entry *entry = NULL;

	a = archive_write_new();

	switch (compression) {
	case 'j': case 'y':
		archive_write_add_filter_bzip2(a);
		break;

	case 'Z':
		archive_write_add_filter_compress(a);
		break;

	case 'z':
		archive_write_add_filter_gzip(a);
		break;

	default:
		archive_write_add_filter_none(a);
		break;
	}

	archive_write_set_format_ustar(a);

	if (filename != NULL && strcmp(filename, "-") == 0) {
		filename = NULL;
	}

	archive_write_open_filename(a, filename);

	struct archive *disk = archive_read_disk_new();
	archive_read_disk_set_standard_lookup(disk);
	int r = 0;

	r = archive_read_disk_open(disk, argv);
	if (r != ARCHIVE_OK) {
		if (asprintf(&message, "%s", archive_error_string(disk)) > 0) {
			log_message(LOG_ERR, message);

			free(message);
			message = NULL;
		}
		return -1;
	}

	for (;;) {
		entry = archive_entry_new();
		if (entry == NULL) {
			break;
		}

		r = archive_read_next_header2(disk, entry);
		if (r == ARCHIVE_EOF) {
			break;
		}

		if (r != ARCHIVE_OK) {
			if (asprintf(&message, "%s", archive_error_string(disk)) > 0) {
				log_message(LOG_ERR, message);

				free(message);
				message = NULL;
			}
			return -1;
		}

		archive_read_disk_descend(disk);

		r = archive_write_header(a, entry);
		if (r < ARCHIVE_OK) {
			if (asprintf(&message, "%s", archive_error_string(a)) > 0) {
				log_message(LOG_ERR, message);

				free(message);
				message = NULL;
			}
		}

		if (r == ARCHIVE_FATAL) {
			return -1;
		}

		if (r > ARCHIVE_FAILED) {
			/* For now, we use a simpler loop to copy data
			 * into the target archive. */
			fd = open(archive_entry_sourcepath(entry), O_RDONLY);
			len = read(fd, buff, sizeof(buff));
			while (len > 0) {
				archive_write_data(a, buff, len);
				len = read(fd, buff, sizeof(buff));
			}
			close(fd);
		}

		archive_entry_free(entry);
		entry = NULL;
	}

	archive_entry_free(entry);
	entry = NULL;

	archive_read_close(disk);
	archive_read_free(disk);
	disk = NULL;

	archive_write_close(a);
	archive_write_free(a);
	a = NULL;

	return 0;
}
