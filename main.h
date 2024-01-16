#include <pspsdk.h>
#include <psputils.h>
#include <pspkerror.h>
#include <psploadcore.h>
#include <psploadexec.h>
#include <psploadexec_kernel.h>
#include <psputility.h>
#include <psputility_modules.h>
#include <psputility_savedata.h>
#include <pspsysmem.h>
#include <pspmodulemgr.h>
#include <pspctrl.h>
#include <pspiofilemgr.h>
#include <string.h>

#ifndef MAIN_H
#define MAIN_H

#define KRAM_BACKUP_SIZE (128*1024) // more than enough to scan sysmem
#define KERNELIFY(x) (((u32)x)|0x80000000)

typedef struct KernelFunctions{
    // iofilemgr.prx Functions
    SceUID (* KernelIOOpen)(const char *, int, int); // 0
    int (* KernelIOWrite)(SceUID, const void *, unsigned); // 4
    int (* KernelIORead)(SceUID, void *, unsigned); // 8
    int (* KernelIOLSeek)(int fd, s64 offset, int whence); // 12
    int (* KernelIOClose)(SceUID); // 16
    SceUID (* KernelIODopen)(char *); // 20
    int (* KernelIODread)(SceUID, SceIoDirent *); // 24
    int (* KernelIODclose)(SceUID); // 28
    int (* KernelIOMkdir)(const char*, SceMode); // 32
    int (* KernelIORmdir)(const char* path); // 36
    int (* KernelIOGetStat)(const char *file, SceIoStat *stat); // 40
    int (* KernelIORemove)(const char* file); // 44
    int (* IoAssign)(const char *dev1, const char *dev2, const char *dev3, int mode, void *unk1, long unk2); // 48
    int (* IoUnassign)(const char *dev); // 52
    
    // sysmem.prx Functions
    SceUID 	(*KernelAllocPartitionMemory)(SceUID partitionid, const char *name, int type, SceSize size, void *addr); // 56
    void * 	(*KernelGetBlockHeadAddr)(SceUID blockid); // 60
    int (* KernelFreePartitionMemory)(int); // 64
    void (* KernelIcacheInvalidateAll)(void); // 68
    void (* KernelDcacheWritebackInvalidateAll)(void); // 72
    int (* KernelGzipDecompress)(unsigned char *dest, unsigned int destSize, const unsigned char *src, void *unknown); // 76
    void (* KernelDcacheInvalidateRange)(const void *p, unsigned int size); // 80

    // loadcore.prx Functions
    void* (* KernelFindModuleByName)(char *); // 84

    // threadman.prx Functions
    SceUID (* KernelCreateThread)(const char *name, SceKernelThreadEntry entry,\
            int initPriority, int stackSize, SceUInt attr, SceKernelThreadOptParam *option); // 88
    int (* KernelStartThread)(SceUID thid, SceSize arglen, void *argp); // 92
    int (* KernelDelayThread)(int); // 96
    int (*KernelDeleteThread)(int); // 100
    int (*KernelExitThread)(int); // 104
    void (*waitThreadEnd)(int, int*); // 108
    
    // ARK functions
    u32 (* FindTextAddrByName)(const char *modulename); // 112
    u32 (* FindFunction)(const char *module, const char *library, u32 nid); // 116
    
}KernelFunctions;

extern KernelFunctions* k_tbl;

// utils.c
void scanKernelFunctions(KernelFunctions* kfuncs);
u32 FindImportRange(char *libname, u32 nid, u32 lower, u32 higher);
u32 FindImportVolatileRam(char *libname, u32 nid);
u32 FindImportUserRam(char *libname, u32 nid);
int p5_open_savedata(int mode);
int p5_close_savedata();
u32 FindFunctionFromUsermode(const char *library, u32 nid, u32 start_addr, u32 end_addr);
u32 FindTextAddrByName(const char *modulename);
u32 FindFunction(const char *module, const char *library, u32 nid);
u32 qwikTrick(char* lib, u32 nid, u32 version);
void _flush_cache();

// kernel_read.c
uint64_t kread64(uint32_t addr);
void dump_kram(u32* dst, u32* src, u32 size);

// kernel_write.c
int stubScanner(u32 patch_addr, u32 orig_instr);
int doExploit();
void executeKernel(u32 kernelContentFunction);

// flash_dumper.c
void initDumperKernelThread();

#endif