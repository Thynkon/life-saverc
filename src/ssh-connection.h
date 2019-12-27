#ifndef SSH_CONNECTION_H
#define SSH_CONNECTION_H

#include <stdio.h>
#include <libssh/libssh.h>

#define USERNAME "thynkon"
#define HOST "127.0.0.1"

#define REMOTE_HOST "127.0.0.1"
#define REMOTE_DIR "/tmp"

extern int ssh_log_level;

struct location {
	int is_ssh;
	char *user;
	char *host;
	char *path;
	ssh_session session;
	ssh_scp scp;
	FILE *file;
};

enum {
	READ,
	WRITE
};

ssh_session connect_ssh(const char *host, const char *user, int verbosity);
int verify_knownhost(ssh_session session);
int authenticate_user(ssh_session session);
void location_free(struct location *loc);
struct location *parse_location(char *loc);
void close_location(struct location *loc);
int open_location(struct location *loc, int flag);
int do_copy(struct location *src, struct location *dest, int recursive);

#endif
