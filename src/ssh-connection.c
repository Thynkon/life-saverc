#define LIBSSH_STATIC 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <regex.h>

#include <sys/stat.h>
#include <libssh/libssh.h>

#include "ssh-connection.h"

int verbosity = SSH_LOG_INFO;

ssh_session connect_ssh(const char *host, const char *user, int verbosity){
	ssh_session session;

	if ((session = ssh_new()) == NULL) {
		return NULL;
	}

	if (user != NULL){
		if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
			ssh_free(session);
			return NULL;
		}
	}

	if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
		ssh_free(session);
		return NULL;
	}

	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	if (ssh_connect(session)) {
		fprintf(stderr, "Connection failed : %s\n", ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);

		return NULL;
	}

	if (verify_knownhost(session) < 0) {
		ssh_disconnect(session);
		ssh_free(session);

		return NULL;
	}

	if (authenticate_user(session) != 0){
		ssh_disconnect(session);
		ssh_free(session);

		return NULL;
	}

	return session;
}

int verify_knownhost(ssh_session session) {
	enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
	rc = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash, &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }

	hexa = ssh_get_hexa(hash, hlen);
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
 
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
			hexa = ssh_get_hexa(hash, hlen);

            fprintf(stderr, "Host key for server changed: it is now:\n");
			fprintf(stderr, "Public key hash %s\n", hash); 
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
 
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);

            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);

            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
 
            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }
 
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }
 
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }

	free(hexa);
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int authenticate_user(ssh_session session) {
	int rc = 0;

	rc = ssh_userauth_publickey_auto(session, NULL, NULL);
	if (rc != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "%s\n", ssh_get_error(session));
	}

	return rc;
}

void location_free(struct location *loc) {
    if (loc != NULL) {
        if (loc->path) {
            free(loc->path);
        }
        loc->path = NULL;

        if (loc->is_ssh) {
            if (loc->host) {
                free(loc->host);
            }
            loc->host = NULL;

            if (loc->user) {
                free(loc->user);
            }
            loc->user = NULL;

            if (loc->host) {
                free(loc->host);
            }
            loc->host = NULL;
        }
        free(loc);
    }
}

struct location *parse_location(char *loc) {
	int str_len = 0;
    struct location *location;

	size_t nmatch = 4; // 3 substrings + 1 (contains full match)
	regex_t preg;
	regmatch_t pmatch[nmatch];

	if (regcomp(&preg, "^(.*)@(.*):(.*)$", REG_EXTENDED) != 0) {
		fprintf(stderr, "Failed to compile regex!\n");
		return NULL;
	}

	if (regexec(&preg, loc, nmatch, pmatch, 0) != 0) {
		fprintf(stderr, "Location %s is invalid!\n", loc);
		regfree(&preg);

		return NULL;
	}

    location = malloc(sizeof(struct location));
    if (location == NULL) {
        return NULL;
    }
    memset(location, 0, sizeof(struct location));

    location->host = location->user = NULL;

	str_len = (pmatch[1].rm_eo -  pmatch[1].rm_so) + 1; // + 1 for '\0' char
	location->user = (char*) malloc(str_len * sizeof(char));
	if (location->user == NULL) {
		return NULL;
	}
	snprintf(location->user, str_len, "%.*s", str_len, loc + pmatch[1].rm_so);

	str_len = (pmatch[2].rm_eo -  pmatch[2].rm_so) + 1; // + 1 for '\0' char
	location->host = (char*) malloc(str_len * sizeof(char));
	if (location->host == NULL) {
		free(location->user);
		location->user = NULL;
		return NULL;
	}
	snprintf(location->host, str_len, "%.*s", str_len, loc + pmatch[2].rm_so);

	str_len = (pmatch[3].rm_eo -  pmatch[3].rm_so) + 1; // + 1 for '\0' char
	location->path = (char*) malloc(str_len * sizeof(char));
	if (location->path == NULL) {
		free(location->user);
		location->user = NULL;

		free(location->host);
		location->host = NULL;

		return NULL;
	}
	snprintf(location->path, str_len, "%.*s", str_len, loc + pmatch[3].rm_so);


	location->is_ssh = 1; // only for now
	regfree(&preg);
	/*
    ptr = strchr(loc, ':');

    if (ptr != NULL) {
        location->is_ssh = 1;
        location->path = strdup(ptr + 1);
        *ptr = '\0';
        ptr = strchr(loc, '@');
		printf("host is %s\n", ptr);

        if (ptr != NULL) {
            location->host = strdup(ptr + 1);
            *ptr = '\0';
            location->user = strdup(loc);
        } else {
            location->host = strdup(loc);
        }
    } else {
        location->is_ssh = 0;
        location->path = strdup(loc);
    }
	*/
    return location;
}

void close_location(struct location *loc) {
    int rc;

    if (loc != NULL) {
        if (loc->is_ssh) {
            if (loc->scp) {
                rc = ssh_scp_close(loc->scp);
                if (rc == SSH_ERROR) {
                    fprintf(stderr,
                            "Error closing scp: %s\n",
                            ssh_get_error(loc->session));
                }
                ssh_scp_free(loc->scp);
                loc->scp = NULL;
            }
            if (loc->session) {
                ssh_disconnect(loc->session);
                ssh_free(loc->session);
                loc->session = NULL;
            }
        } else {
            if (loc->file) {
                fclose(loc->file);
                loc->file = NULL;
            }
        }
    }
}

int open_location(struct location *loc, int flag) {
    if (loc->is_ssh && flag == WRITE) {
        loc->session = connect_ssh(loc->host, loc->user, verbosity);
        if (!loc->session) {
            fprintf(stderr, "Couldn't connect to %s\n", loc->host);
            return -1;
        }

        loc->scp = ssh_scp_new(loc->session, SSH_SCP_WRITE, loc->path);
        if (!loc->scp) {
            fprintf(stderr, "error : %s\n", ssh_get_error(loc->session));
            ssh_disconnect(loc->session);
            ssh_free(loc->session);
            loc->session = NULL;
            return -1;
        }

        if (ssh_scp_init(loc->scp) == SSH_ERROR) {
            fprintf(stderr, "error : %s\n", ssh_get_error(loc->session));
            ssh_scp_free(loc->scp);
            loc->scp = NULL;

            ssh_disconnect(loc->session);
            ssh_free(loc->session);

            loc->session = NULL;

            return -1;
        }
        return 0;
    } else if (loc->is_ssh && flag == READ) {
        loc->session = connect_ssh(loc->host, loc->user, verbosity);

        if (!loc->session) {
            fprintf(stderr, "Couldn't connect to %s\n", loc->host);
            return -1;
        }

        loc->scp = ssh_scp_new(loc->session, SSH_SCP_READ, loc->path);
        if (!loc->scp) {
            fprintf(stderr, "error : %s\n", ssh_get_error(loc->session));
            ssh_disconnect(loc->session);
            ssh_free(loc->session);
            loc->session = NULL;
            return -1;
        }

        if (ssh_scp_init(loc->scp) == SSH_ERROR) {
            fprintf(stderr, "error : %s\n", ssh_get_error(loc->session));
            ssh_scp_free(loc->scp);
            loc->scp = NULL;
            ssh_disconnect(loc->session);
            ssh_free(loc->session);
            loc->session = NULL;
            return -1;
        }
        return 0;
    } else {
        loc->file = fopen(loc->path, flag == READ ? "r":"w");
        if (!loc->file) {
            if (errno == EISDIR) {
                if (chdir(loc->path)) {
                    fprintf(stderr,
                            "Error changing directory to %s: %s\n",
                            loc->path, strerror(errno));
                    return -1;
                }
                return 0;
            }
            fprintf(stderr,
                    "Error opening %s: %s\n",
                    loc->path, strerror(errno));
            return -1;
        }
        return 0;
    }
    return -1;
}

/** @brief copies files from source location to destination
 * @param src source location
 * @param dest destination location
 * @param recursive Copy also directories
 */
int do_copy(struct location *src, struct location *dest, int recursive) {
    size_t size;
    socket_t fd;
    struct stat s;
    int w, r;
    char buffer[16384];
    size_t total = 0;
    mode_t mode;
    char *filename = NULL;

    /* recursive mode doesn't work yet */
    (void)recursive;
    /* Get the file name and size*/
    if (!src->is_ssh) {
        fd = fileno(src->file);
        if (fd < 0) {
            fprintf(stderr,
                    "Invalid file pointer, error: %s\n",
                    strerror(errno));
            return -1;
        }
        r = fstat(fd, &s);
        if (r < 0) {
            return -1;
        }
        size = s.st_size;
        mode = s.st_mode & ~S_IFMT;
        filename = ssh_basename(src->path);
    } else {
        size = 0;
        do {
            r = ssh_scp_pull_request(src->scp);
            if (r == SSH_SCP_REQUEST_NEWDIR) {
                ssh_scp_deny_request(src->scp, "Not in recursive mode");
                continue;
            }
            if (r == SSH_SCP_REQUEST_NEWFILE) {
                size = ssh_scp_request_get_size(src->scp);
                filename = strdup(ssh_scp_request_get_filename(src->scp));
                mode = ssh_scp_request_get_permissions(src->scp);
                //ssh_scp_accept_request(src->scp);
                break;
            }
            if (r == SSH_ERROR) {
                fprintf(stderr,
                        "Error: %s\n",
                        ssh_get_error(src->session));
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        } while(r != SSH_SCP_REQUEST_NEWFILE);
    }

    if (dest->is_ssh) {
        r = ssh_scp_push_file(dest->scp, src->path, size, mode);
        //  snprintf(buffer, sizeof(buffer), "C0644 %d %s\n", size, src->path);
        if (r == SSH_ERROR) {
            fprintf(stderr,
                    "error: %s\n",
                    ssh_get_error(dest->session));
            SSH_STRING_FREE_CHAR(filename);
            ssh_scp_free(dest->scp);
            dest->scp = NULL;
            return -1;
        }
    } else {
        if (!dest->file) {
            dest->file = fopen(filename, "w");
            if (!dest->file) {
                fprintf(stderr,
                        "Cannot open %s for writing: %s\n",
                        filename, strerror(errno));
                if (src->is_ssh) {
                    ssh_scp_deny_request(src->scp, "Cannot open local file");
                }
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        }
        if (src->is_ssh) {
            ssh_scp_accept_request(src->scp);
        }
    }

    do {
        if (src->is_ssh) {
            r = ssh_scp_read(src->scp, buffer, sizeof(buffer));
            if (r == SSH_ERROR) {
                fprintf(stderr,
                        "Error reading scp: %s\n",
                        ssh_get_error(src->session));
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }

            if (r == 0) {
                break;
            }
        } else {
            r = fread(buffer, 1, sizeof(buffer), src->file);
            if (r == 0) {
                break;
            }

            if (r < 0) {
                fprintf(stderr,
                        "Error reading file: %s\n",
                        strerror(errno));
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        }

        if (dest->is_ssh) {
            w = ssh_scp_write(dest->scp, buffer, r);
            if (w == SSH_ERROR) {
                fprintf(stderr,
                        "Error writing in scp: %s\n",
                        ssh_get_error(dest->session));
                ssh_scp_free(dest->scp);
                dest->scp = NULL;
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        } else {
            w = fwrite(buffer, r, 1, dest->file);
            if (w <= 0) {
                fprintf(stderr,
                        "Error writing in local file: %s\n",
                        strerror(errno));
                SSH_STRING_FREE_CHAR(filename);
                return -1;
            }
        }
        total += r;

    } while(total < size);

    SSH_STRING_FREE_CHAR(filename);
    printf("wrote %zu bytes\n", total);

    return 0;
}
