TARGET = flash_dumper
OBJS = main.o utils.o kernel_read.o kernel_write.o flash_dumper.o imports.o

CFLAGS = -O2 -Os -G0 -Wall -std=c99
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS)

BUILD_PRX = 1

EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = PSP Flash Dumper

LIBDIR = 
LIBS = -lpsprtc

PSPSDK = $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak