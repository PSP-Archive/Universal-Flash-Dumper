#include "main.h"

PSP_MODULE_INFO("Flash Dumper", PSP_MODULE_USER, 1, 0);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER | PSP_THREAD_ATTR_VFPU);

u32* kram_copy = NULL;
SceUID memid = -1;

static KernelFunctions _ktbl;
KernelFunctions* k_tbl = &_ktbl;

void ktest(){
    pspDebugScreenPrintf("Got Kernel Access!\n");
    scanKernelFunctions(k_tbl);
    repairInstruction();
    initDumperKernelThread();
}

int main(){ 

    pspDebugScreenInit();

    pspDebugScreenPrintf("Universal Flash Dumper Started.\n");

    memid = sceKernelAllocPartitionMemory(PSP_MEMORY_PARTITION_USER, "", PSP_SMEM_High, KRAM_BACKUP_SIZE, NULL);
    kram_copy = sceKernelGetBlockHeadAddr(memid);

    pspDebugScreenPrintf("Dumping kernel RAM for analysis.\n");
    dump_kram(kram_copy, 0x88000000, KRAM_BACKUP_SIZE);

    pspDebugScreenPrintf("Analyzing kernel RAM to obtain offset of sceKernelLibcTime\n");
    u32 libctime_addr = FindFunctionFromUsermode("UtilsForUser", 0x27CC57F0, (u32)kram_copy, (u32)kram_copy + KRAM_BACKUP_SIZE);

    pspDebugScreenPrintf("Found address of sceKernelLibcTime at: %p\n", libctime_addr);

    u32 libctime_offset = libctime_addr - 0x88000000;
    u32 orig_inst = *(u32*)( (u32)kram_copy + libctime_offset + 4 );

    stubScanner(libctime_addr+4, orig_inst);
    doExploit();
    executeKernel(&ktest);

    pspDebugScreenPrintf("All Done! Press any button to exit\n");

    while (1){
        SceCtrlData pad;
        sceCtrlReadBufferPositive(&pad, 1);
        if (pad.Buttons) break;
    }

    sceKernelExitGame();

    return 0;
}