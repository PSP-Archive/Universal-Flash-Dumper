#include "libpspexploit.h"

// flash_dumper.c
void initDumperKernelThread();

PSP_MODULE_INFO("Flash Dumper", PSP_MODULE_USER, 1, 0);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER | PSP_THREAD_ATTR_VFPU);

static KernelFunctions _ktbl;
KernelFunctions* k_tbl = &_ktbl;

void kmain(){
    int k1 = pspSdkSetK1(0);
    pspDebugScreenPrintf("Got Kernel Access!\n");
    scanKernelFunctions(k_tbl);
    repairKernel();
    initDumperKernelThread();
    pspDebugScreenPrintf("All Done!\n");
    pspSdkSetK1(k1);
}

int main(){

    int res = 0;

    pspDebugScreenInit();

    pspDebugScreenPrintf("Universal Flash Dumper Started.\n");
    
    pspDebugScreenPrintf("Initializing kernel exploit...\n");
    res = initExploit();

    if (res == 0){

        pspDebugScreenPrintf("Corrupting kernel...\n");
        res = doExploit();
        
        if (res == 0){
            executeKernel(kmain);
        }
        else {
            pspDebugScreenPrintf("ERROR: %p", res);
        }
    
    }
    else{
        pspDebugScreenPrintf("ERROR: %p\n", res);
    }

    pspDebugScreenPrintf("Press any button to exit\n");
    SceCtrlData pad;
    while (1){
        sceCtrlReadBufferPositive(&pad, 1);
        if (pad.Buttons) break;
    }

    sceKernelExitGame();
    return 0;
}
