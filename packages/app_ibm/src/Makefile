BIN:=app_ibm
LDFLAGS:=-liotp-as-device -lblobmsg_json -lubox -lubus
SRC:=$(wildcard *.c)
OBJS:=$(SRC:.c=.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) 
clean:
	rm -f $(BIN) $(OBJS)
