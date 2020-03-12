#ifndef VERBOSE_H
#define VERBOSE_H

extern int verbose;
extern int log_level;

void log_message(int priority, char* message);

#endif
