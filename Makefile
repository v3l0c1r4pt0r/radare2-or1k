ASM_NAME=asm_or1k
ANAL_NAME=anal_or1k
R2_PLUGIN_PATH=$(shell r2 -H|grep USER_PLUGINS|awk '{print $$2}')
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_anal)
LDFLAGS=-shared $(shell pkg-config --libs r_anal)
ASM_OBJS=$(ASM_NAME).o
ANAL_OBJS=$(ANAL_NAME).o
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
ASM_LIB=$(ASM_NAME).$(SO_EXT)
ANAL_LIB=$(ANAL_NAME).$(SO_EXT)

all: $(ASM_LIB) $(ANAL_LIB)

clean:
	rm -f $(ASM_LIB) $(ANAL_LIB) $(ASM_OBJS)

$(ASM_LIB): $(ASM_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(ASM_OBJS) -o $(ASM_LIB)

$(ANAL_LIB): $(ANAL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(ANAL_OBJS) -o $(ANAL_LIB)

install:
	cp -f $(ASM_NAME).$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/$(ASM_NAME).$(SO_EXT)
