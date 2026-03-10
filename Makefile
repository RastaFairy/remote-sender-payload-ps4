LIBPS4  := $(PS4SDK)/libPS4
CC      := gcc
OBJCOPY := objcopy
ODIR    := build
SDIR    := source
IDIRS   := -I$(LIBPS4)/include -Iinclude
LDIRS   := -L$(LIBPS4)
MAPFILE := $(shell basename $(CURDIR)).map

CFLAGS  := $(IDIRS) -Os -std=gnu11 -ffunction-sections -fdata-sections \
            -fno-builtin -nostartfiles -nostdlib -Wall -masm=intel \
            -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small -fpie

LFLAGS  := $(LDIRS) -Xlinker -T $(LIBPS4)/linker.x \
            -Xlinker -Map=$(MAPFILE) -Wl,--build-id=none -Wl,--gc-sections

CFILES  := $(wildcard $(SDIR)/*.c)
SFILES  := $(wildcard $(SDIR)/*.s)
OBJS    := $(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(CFILES)) \
           $(patsubst $(SDIR)/%.s, $(ODIR)/%.o, $(SFILES))
LIBS    := -lPS4
TARGET  := pkgsender.bin

.PHONY: all clean

all: $(ODIR) $(TARGET)

$(TARGET): $(OBJS)
	@echo "  LD  $(TARGET)"
	$(CC) $(LIBPS4)/crt0.s $(ODIR)/*.o -o $(ODIR)/temp.elf $(CFLAGS) $(LFLAGS) $(LIBS)
	$(OBJCOPY) -O binary $(ODIR)/temp.elf $(TARGET)
	@rm -f $(ODIR)/temp.elf $(MAPFILE)
	@echo "  OK  $(TARGET)"

$(ODIR)/%.o: $(SDIR)/%.c
	@echo "  CC  $<"
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR):
	@mkdir -p $(ODIR)

clean:
	@rm -rf $(ODIR) $(TARGET) $(MAPFILE)
	@echo "  clean OK"
