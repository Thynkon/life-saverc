# Define C compiler
CC=gcc
# Compilation flags
CFLAGS = -Wall -g

# Define library paths in addition to /usr/lib
LFLAGS = -L/usr/lib64
LIBS = -larchive -lssh

SRCS = src/*.c

# Executable's name
MAIN = life-saverc

all: $(MAIN)
	@echo $(MAIN) has been successfully compiled

$(MAIN): $(OBJS)
	$(CC) $(CFLAGS) $(SRCS) -o $(MAIN) $(LFLAGS) $(LIBS)

clean:
	$(RM) *~ $(MAIN)
