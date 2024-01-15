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

#define KRAM_BACKUP_SIZE (512*1024)
#define KERNELIFY(x) (((u32)x)|0x80000000)

typedef struct KernelFunctions{
    // iofilemgr.prx Functions
    SceUID (* KernelIOOpen)(const char *, int, int);
    int (* KernelIOWrite)(SceUID, const void *, unsigned);
    int (* KernelIORead)(SceUID, void *, unsigned);
    int (* KernelIOLSeek)(int fd, s64 offset, int whence);
    int (* KernelIOClose)(SceUID);
    SceUID (* KernelIODopen)(char *);
    int (* KernelIODread)(SceUID, SceIoDirent *);
    int (* KernelIODclose)(SceUID);
    int (* KernelIOMkdir)(const char*, SceMode);
    int (* KernelIORmdir)(const char* path);
    int (* KernelIOGetStat)(const char *file, SceIoStat *stat);
    int (* KernelIORemove)(const char* file);
    int (* IoAssign)(const char *dev1, const char *dev2, const char *dev3, int mode, void *unk1, long unk2);
    int (* IoUnassign)(const char *dev);
    
    // sysmem.prx Functions
    SceUID 	(*KernelAllocPartitionMemory)(SceUID partitionid, const char *name, int type, SceSize size, void *addr);
    void * 	(*KernelGetBlockHeadAddr)(SceUID blockid);
    int (* KernelFreePartitionMemory)(int);
    void (* KernelIcacheInvalidateAll)(void);
    void (* KernelDcacheWritebackInvalidateAll)(void);
    int (* KernelGzipDecompress)(unsigned char *dest, unsigned int destSize, const unsigned char *src, void *unknown);
    void (* KernelDcacheInvalidateRange)(const void *p, unsigned int size);

    // loadcore.prx Functions
    void* (* KernelFindModuleByName)(char *);

    // threadman.prx Functions
    SceUID (* KernelCreateThread)(const char *name, SceKernelThreadEntry entry,\
            int initPriority, int stackSize, SceUInt attr, SceKernelThreadOptParam *option);
    int (* KernelStartThread)(SceUID thid, SceSize arglen, void *argp);
    int (* KernelDelayThread)(int);
    int (*KernelDeleteThread)(int);
    int (*KernelExitThread)(int);
    void (*waitThreadEnd)(int, int*);
    
    // ARK functions
    u32 (* FindTextAddrByName)(const char *modulename);
    u32 (* FindFunction)(const char *module, const char *library, u32 nid);
    
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