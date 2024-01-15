#include "main.h"

/*
 * These functions are ment for using when initial kernel access has been
 * granted, for example through the mean of a kernel exploit.
 */
void scanKernelFunctions(KernelFunctions* kfuncs){

    memset(kfuncs, 0, sizeof(KernelFunctions));

    kfuncs->KernelIOOpen = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x109F50BC);
    kfuncs->KernelIORead = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x6A638D83);
    kfuncs->KernelIOLSeek = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x27EB27B8);
    kfuncs->KernelIOClose = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x810C4BC3);
    kfuncs->KernelIOWrite = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x42EC03AC);
    kfuncs->KernelIOMkdir = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x06A70004);
    kfuncs->KernelIORmdir = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x1117C65F);
    kfuncs->KernelIODopen = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0xB29DDF9C);
    kfuncs->KernelIODread = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0xE3EB004C);
    kfuncs->KernelIODclose = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0xEB092469);
    kfuncs->KernelIOGetStat = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0xACE946E8);
    kfuncs->KernelIORemove = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0xF27A9C51);
    kfuncs->IoAssign = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0xB2A628C1);
    kfuncs->IoUnassign = (void*)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x6D08A871);
    
    kfuncs->KernelAllocPartitionMemory = (void*)FindFunction("sceSystemMemoryManager", "SysMemForKernel", 0x237DBD4F);
    kfuncs->KernelGetBlockHeadAddr = (void*)FindFunction("sceSystemMemoryManager", "SysMemForKernel", 0x9D9A5BA1);
    kfuncs->KernelFreePartitionMemory = (void*)FindFunction("sceSystemMemoryManager", "SysMemForKernel", 0xB6D61D02);
    kfuncs->KernelIcacheInvalidateAll = (void*)FindFunction("sceSystemMemoryManager", "UtilsForKernel", 0x920F104A);
    kfuncs->KernelDcacheWritebackInvalidateAll = (void*)FindFunction("sceSystemMemoryManager", "UtilsForKernel", 0xB435DEC5);
    kfuncs->KernelDcacheInvalidateRange = (void*)FindFunction("sceSystemMemoryManager", "UtilsForKernel", 0xBFA98062);
    kfuncs->KernelGzipDecompress = (void*)FindFunction("sceSystemMemoryManager", "UtilsForKernel", 0x78934841);
    
    kfuncs->KernelFindModuleByName = (void*)FindFunction("sceLoaderCore", "LoadCoreForKernel", 0xF6B1BF0F);
    
    kfuncs->KernelCreateThread = (void*)FindFunction("sceThreadManager", "ThreadManForKernel", 0x446D8DE6);
    kfuncs->KernelStartThread = (void*)FindFunction("sceThreadManager", "ThreadManForKernel", 0xF475845D);
    kfuncs->KernelDelayThread = (void*)FindFunction("sceThreadManager", "ThreadManForKernel", 0xCEADEB47);
    kfuncs->KernelExitThread = (void*)FindFunction("sceThreadManager", "ThreadManForKernel", 0xAA73C935);
    kfuncs->KernelDeleteThread = (void*)FindFunction("sceThreadManager", "ThreadManForKernel", 0x9FA03CD3);
    kfuncs->waitThreadEnd = (void*)FindFunction("sceThreadManager", "ThreadManForKernel", 0x278C0DF5);
    
    // ARK kernel functions
    kfuncs->FindTextAddrByName = &FindTextAddrByName;
    kfuncs->FindFunction = &FindFunction;
}


int AddressInRange(u32 addr, u32 lower, u32 higher){
    return (addr >= lower && addr < higher);
}

u32 FindImportRange(char *libname, u32 nid, u32 lower, u32 higher){
    u32 i;
    for(i = lower; i < higher; i += 4) {
        SceLibraryStubTable *stub = (SceLibraryStubTable *)i;

        if((stub->libname != libname) && AddressInRange((u32)stub->libname, lower, higher) \
            && AddressInRange((u32)stub->nidtable, lower, higher) && AddressInRange((u32)stub->stubtable, lower, higher)) {
            if(strcmp(libname, stub->libname) == 0) {
                u32 *table = stub->nidtable;

                int j;
                for(j = 0; j < stub->stubcount; j++) {
                    if(table[j] == nid) {
                        return ((u32)stub->stubtable + (j * 8));
                    }
                }
            }
        }
    }

    return 0;
}

u32 FindImportVolatileRam(char *libname, u32 nid){
    return FindImportRange(libname, nid, 0x08400000, 0x08800000);
}

u32 FindImportUserRam(char *libname, u32 nid){
    return FindImportRange(libname, nid, 0x08800000, 0x0A000000);
}

int p5_open_savedata(int mode)
{
    p5_close_savedata();

    SceUtilitySavedataParam dialog;

    memset(&dialog, 0, sizeof(SceUtilitySavedataParam));
    dialog.base.size = sizeof(SceUtilitySavedataParam);

    dialog.base.language = 1;
    dialog.base.buttonSwap = 1;
    dialog.base.graphicsThread = 0x11;
    dialog.base.accessThread = 0x13;
    dialog.base.fontThread = 0x12;
    dialog.base.soundThread = 0x10;

    dialog.mode = mode;

    sceUtilitySavedataInitStart(&dialog);

    // Wait for the dialog to initialize
    int status;
    while ((status = sceUtilitySavedataGetStatus()) < 2)
    {
        sceKernelDelayThread(100);
        if (status < 0) return 0; // error
    }
    return 1;
}

// Runs the savedata dialog loop
int p5_close_savedata()
{

    int running = 1;
    int last_status = -1;

    while(running) 
    {
        int status = sceUtilitySavedataGetStatus();
        
        if (status != last_status)
        {
            last_status = status;
        }
        switch(status)
        {
            case PSP_UTILITY_DIALOG_VISIBLE:
                sceUtilitySavedataUpdate(1);
                break;

            case PSP_UTILITY_DIALOG_QUIT:
                sceUtilitySavedataShutdownStart();
                break;

            case PSP_UTILITY_DIALOG_NONE:
                running = 0;
                break;

            case PSP_UTILITY_DIALOG_FINISHED:
                break;
            default:
                if (status < 0) // sceUtilitySavedataGetStatus returned error?
                    return 0;
                break;
        }
        sceKernelDelayThread(100);
    }
    return 1;
}

u32 FindFunctionFromUsermode(const char *library, u32 nid, u32 start_addr, u32 end_addr)
{
    u32 addr = start_addr;
    
    if (addr) {
        u32 maxaddr = end_addr;
        for (; addr < maxaddr; addr += 4) {
            if (strcmp(library, (const char *)addr) == 0) {
                
                u32 libaddr = (addr-start_addr-4) + 0x88000000;

                while (*(u32*)(addr -= 4) != libaddr) {
                    if (addr <= start_addr){
                        return 0;
                    }
                };

                u32 exports = (u32)(*(u16*)(addr + 10) + *(u8*)(addr + 9));
                u32 jump = exports * 4;

                addr = *(u32*)(addr + 12);
                addr -= 0x88000000;
                addr += start_addr;

                while (exports--) {
                    if (*(u32*)addr == nid){
                        return *(u32*)(addr + jump);
                    }
                    addr += 4;
                }

                return 0;
            }
        }
    }
    return 0;
}

u32 FindTextAddrByName(const char *modulename)
{
    u32 kaddr;
    for (kaddr = 0x88000000; kaddr < 0x88400000; kaddr += 4) {
        if (strcmp((const char *)kaddr, modulename) == 0) {
            if ((*(u32*)(kaddr + 0x64) == *(u32*)(kaddr + 0x78)) && \
                (*(u32*)(kaddr + 0x68) == *(u32*)(kaddr + 0x88))) {
                if (*(u32*)(kaddr + 0x64) && *(u32*)(kaddr + 0x68))
                    return *(u32*)(kaddr + 0x64);
            }
        }
    }
    return 0;
}

u32 FindFunction(const char *module, const char *library, u32 nid)
{
    u32 addr = FindTextAddrByName(module);
    
    if (addr) {
        u32 maxaddr = 0x88400000;
        for (; addr < maxaddr; addr += 4) {
            if (strcmp(library, (const char *)addr) == 0) {
                
                u32 libaddr = addr;

                while (*(u32*)(addr -= 4) != libaddr);

                u32 exports = (u32)(*(u16*)(addr + 10) + *(u8*)(addr + 9));
                u32 jump = exports * 4;

                addr = *(u32*)(addr + 12);

                while (exports--) {
                    if (*(u32*)addr == nid){
                        return *(u32*)(addr + jump);
                    }
                    addr += 4;
                }

                return 0;
            }
        }
    }
    return 0;
}