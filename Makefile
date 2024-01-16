TARGET = flash_dumper
OBJS = main.o utils.o kernel_read.o kernel_write.o flash_dumper.o imports.o

UNAME := $(shell uname)


release: all
ifeq ($(UNAME), Linux)
	WINEPREFIX=$(shell pwd)/prefix wine $(shell pwd)/bin/prxEncrypter.exe $(TARGET).prx
else
	$(shell pwd)\bin\prxEncrypter $(TARGET).prx
endif
	pack-pbp $(EXTRA_TARGETS) PARAM.SFO NULL NULL NULL NULL NULL data.psp NULL

	

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
