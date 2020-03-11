OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= /usr/bin/bpftool
INCLUDES := -I$(OUTPUT)
CFLAGS := -O3 -Os -fdata-sections -ffunction-sections -fvisibility=hidden
LDFLAGS := -Wl,--gc-sections -static -lbpf -lelf -lz
# Most distros don't currently ship with CONFIG_DEBUG_INFO_BTF enabled
# so set BPF_NO_PRESERVE_ACCESS_INDEX so we don't have to relocate
# any structures from vmlinux.h -- what this means is that we can only
# use ABI-stable structures (like registers). Since, for example, retrieving
# arguments to uprobes, requires navigating the task->thread->sp chain
# this means that uprobes or anything of the like aren't currently possible
# if you want to use non-stable kernel structures. Once CONFIG_DEBUG_INFO_BTF
# gets turned on by default, then we can do all sorts of things.
BPFFLAGS := -g -O2 -target bpf -DBPF_NO_PRESERVE_ACCESS_INDEX=1
LIB = libprobe.a
SOURCES = probe.c
BPF_SOURCES = probe.bpf.c
OBJECTS = $(SOURCES:%.c=$(OUTPUT)/%.o)
BPF_OBJECTS = $(BPF_SOURCES:%.bpf.c=$(OUTPUT)/%.bpf.o)
BPF_HEADERS = $(BPF_SOURCES:%.bpf.c=$(OUTPUT)/%.skel.h)

.PHONY: all
all: $(OUTPUT)/$(LIB)

.PHONY: clean
clean:
	rm -rf $(OUTPUT)

$(OUTPUT):
	mkdir -p $@

$(OUTPUT)/$(LIB): $(OBJECTS) $(BPF_OBJECTS)
	$(AR) rcs $@ $(OBJECTS) $(BPF_OBJECTS)

$(OUTPUT)/%.o: %.c | $(BPF_HEADERS)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(BPF_OBJECTS)
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard %.h) | $(OUTPUT)
	$(CLANG) $(BPFFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@ &&				      \
	$(LLVM_STRIP) -g $@

