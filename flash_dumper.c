#include "main.h"

#define BUF_SIZE 1024*32


#define PSP_NAND_PAGES_PER_BLOCK		32
#define PSP_NAND_PAGE_USER_SIZE		    512
#define PSP_IPL_SIGNATURE			    0x6DC64A38
#define PSP_NAND_PAGE_SPARE_SIZE		16
#define PSP_NAND_PAGE_SPARE_SMALL_SIZE	(PSP_NAND_PAGE_SPARE_SIZE-4)
#define PSP_NAND_BLOCK_USER_SIZE		(PSP_NAND_PAGE_USER_SIZE*PSP_NAND_PAGES_PER_BLOCK)
#define PSP_NAND_BLOCK_SPARE_SMALL_SIZE	(PSP_NAND_PAGE_SPARE_SMALL_SIZE*PSP_NAND_PAGES_PER_BLOCK)

u8  user[PSP_NAND_BLOCK_USER_SIZE], spare[PSP_NAND_BLOCK_SPARE_SMALL_SIZE];
u8 orig_ipl[0x24000] __attribute__((aligned(64)));

int (*NandLock)(int) = NULL;
int (*NandUnlock)() = NULL;
int (*NandReadPagesRawAll)(u32, u8*, u8*, int) = NULL;
int (*NandReadBlockWithRetry)(u32, u8*, void*) = NULL;

int (*IdStorageReadLeaf)(u16, u8*);
int (*KernelGetUserLevel)();

u8 seed[0x100];
// sigcheck keys
u8 check_keys0[0x10] = {
    0x71, 0xF6, 0xA8, 0x31, 0x1E, 0xE0, 0xFF, 0x1E,
    0x50, 0xBA, 0x6C, 0xD2, 0x98, 0x2D, 0xD6, 0x2D
};

u8 check_keys1[0x10] = {
    0xAA, 0x85, 0x4D, 0xB0, 0xFF, 0xCA, 0x47, 0xEB,
    0x38, 0x7F, 0xD7, 0xE4, 0x3D, 0x62, 0xB0, 0x10
};

u8* bigbuf = (u8*)0x8930000;

int (*BufferCopyWithRange)(void*, int, void*, int, int);

static inline void open_flash(){
    while(k_tbl->IoUnassign("flash0:") < 0) {
        k_tbl->KernelDelayThread(500000);
    }
    while (k_tbl->IoAssign("flash0:", "lflash0:0,0", "flashfat0:", 0, NULL, 0)<0){
        k_tbl->KernelDelayThread(500000);
    }

    int ret;

    ret = k_tbl->IoUnassign("flash3:");

    while(ret < 0 && ret != SCE_KERNEL_ERROR_NODEV) {
        ret = k_tbl->IoUnassign("flash3:");
        k_tbl->KernelDelayThread(500000);
    }

    k_tbl->IoAssign("flash3:", "lflash0:0,3", "flashfat3:", 0, NULL, 0);
}

int fileExists(const char* path){
    int fp = k_tbl->KernelIOOpen(path, PSP_O_RDONLY, 0777);
    if (fp < 0)
        return 0;
    k_tbl->KernelIOClose(fp);
    return 1;
}

int folderExists(const char* path){
    int fp = k_tbl->KernelIODopen(path);
    if (fp < 0)
        return 0;
    k_tbl->KernelIODclose(fp);
    return 1;
}

static int Decrypt(u32 *buf, int size)
{
    buf[0] = 5;
    buf[1] = buf[2] = 0;
    buf[3] = 0x100;
    buf[4] = size;

    if (BufferCopyWithRange((u8*)buf, size+0x14, (u8*)buf, size+0x14, 8) != 0)
        return -1;

    return 0;
}

int pspUnsignCheck(u8 *buf)
{
    u8 enc[0xD0+0x14];
    int iXOR, res;

    memcpy(enc+0x14, buf+0x80, 0xD0);

    for (iXOR = 0; iXOR < 0xD0; iXOR++)
    {
        enc[iXOR+0x14] ^= check_keys1[iXOR&0xF]; 
    }

    if ((res = Decrypt((u32 *)enc, 0xD0)) < 0)
    {
        return res;
    }

    for (iXOR = 0; iXOR < 0xD0; iXOR++)
    {
        enc[iXOR] ^= check_keys0[iXOR&0xF];
    }

    memcpy(buf+0x80, enc+0x40, 0x90);
    memcpy(buf+0x110, enc, 0x40);

    return 0;
}

void copyFile(char* path, char* destination){

    SceUID src = k_tbl->KernelIOOpen(path, PSP_O_RDONLY, 0777);
    SceUID dst = k_tbl->KernelIOOpen(destination, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);

    int len = strlen(path);
    int read;

    if (strcmp(&path[len-4], ".prx") == 0){
        size_t fsize = k_tbl->KernelIOLSeek(src, 0, PSP_SEEK_END);
        k_tbl->KernelIOLSeek(src, 0, PSP_SEEK_SET);
        read = k_tbl->KernelIORead(src, bigbuf, fsize);
        pspUnsignCheck(bigbuf);
        k_tbl->KernelIOWrite(dst, bigbuf, read);
    }
    else{
        size_t fsize = k_tbl->KernelIOLSeek(src, 0, PSP_SEEK_END);
		k_tbl->KernelIOLSeek(src, 0, PSP_SEEK_SET);
        do {
            read = k_tbl->KernelIORead(src, bigbuf, BUF_SIZE);
            k_tbl->KernelIOWrite(dst, bigbuf, read);
        } while (read > 0);
    }

    k_tbl->KernelIOClose(src);
    k_tbl->KernelIOClose(dst);
}

int copy_folder_recursive(const char * source, const char * destination)
{

    //create new folder
    k_tbl->KernelIOMkdir(destination, 0777);
    
    int src_len = strlen(source);
    int dst_len = strlen(destination);

    char new_destination[256];
    strcpy(new_destination, destination);
    if (new_destination[dst_len-1] != '/'){
        new_destination[dst_len] = '/';
        new_destination[dst_len+1] = 0;
    }
    
    char new_source[256];
    strcpy(new_source, source);
    if (new_source[src_len-1] != '/'){
        new_source[src_len] = '/';
        new_source[src_len+1] = 0;
    }

    //try to open source folder
    SceUID dir = k_tbl->KernelIODopen(source);
    
    if(dir >= 0)
    {
        SceIoDirent entry;
        memset(&entry, 0, sizeof(SceIoDirent));
        
        //start reading directory entries
        while(k_tbl->KernelIODread(dir, &entry) > 0)
        {
            //skip . and .. entries
            if (!strcmp(".", entry.d_name) || !strcmp("..", entry.d_name)) 
            {
                memset(&entry, 0, sizeof(SceIoDirent));
                continue;
            };

            char src[255];
            strcpy(src, new_source);
            strcat(src, entry.d_name);

            char dst[255];
            strcpy(dst, new_destination);
            strcat(dst, entry.d_name);

            if (fileExists(src))
            { //is it a file
                pspDebugScreenPrintf("Copying file %s\n", src);
                copyFile(src, dst); //copy file
            }
            else if (folderExists(src))
            {
                //try to copy as a folder
                pspDebugScreenPrintf("Copying folder %s\n", src);
                copy_folder_recursive(src, dst);
            }

        };
        //close folder
        k_tbl->KernelIODclose(dir);
    };
    
    return 1;
};

int pspIplGetIpl(u8 *buf)
{
	u32 block, ppn;
	u16	blocktable[32];
	int i, res, nblocks, size;

	for (block = 4; block < 0x0C; block++)
	{
		ppn = block*PSP_NAND_PAGES_PER_BLOCK;		
		res = NandReadPagesRawAll(ppn, user, spare, 1);
		if (res < 0)
		{
			//Printf("   Error reading page 0x%04X.\n", ppn);
			return res;
		}

		if (spare[5] == 0xFF) // if good block 
		{
			if (*(u32 *)&spare[8] == PSP_IPL_SIGNATURE)
				break;
		}
	}

	if (block == 0x0C)
	{
		//Printf("   Cannot find IPL in nand!.\n");
		return -1;
	}

	for (nblocks = 0; nblocks < 32; nblocks++)
	{
		blocktable[nblocks] = *(u16 *)&user[nblocks*2];
		
		if (blocktable[nblocks] == 0)
			break;		
	}

	size = 0;

	for (i = 0; i < nblocks; i++)
	{
		ppn = blocktable[i]*PSP_NAND_PAGES_PER_BLOCK;
		res = NandReadBlockWithRetry(ppn, buf, NULL);
		if (res < 0)
		{
			//Printf("   Cannot read block ppn=0x%04.\n", ppn);
			return res;
		}

		buf += PSP_NAND_BLOCK_USER_SIZE;
		
		size += PSP_NAND_BLOCK_USER_SIZE;
	}
	
	return size;
}


// Set User Level
int sctrlKernelSetUserLevel(int level)
{
    
    // Backup User Level
    int previouslevel = KernelGetUserLevel();
    
    u32 _sceKernelReleaseThreadEventHandler = FindFunction("sceThreadManager", "ThreadManForUser", 0x72F3C145);

    u32 addr = _sceKernelReleaseThreadEventHandler + 0x4;
    do {
        addr += 4;
    } while ((_lw(addr)&0xFFF00000) != 0x24B00000);
    
    u32 threadman_userlevel_struct = _lh(_sceKernelReleaseThreadEventHandler + 0x4)<<16;
    threadman_userlevel_struct += (short)_lh(addr);

    // Set User Level
    _sw((level ^ 8) << 28, *(unsigned int *)(threadman_userlevel_struct) + 0x14);
    
    // Flush Cache
    k_tbl->KernelDcacheWritebackInvalidateAll();
    
    // Return previous User Level
    return previouslevel;
}

int dcIdStorageReadLeaf(u16 leafid, u8 *buf)
{
    int level = sctrlKernelSetUserLevel(8);

    int res = IdStorageReadLeaf(leafid, buf);

    sctrlKernelSetUserLevel(level);

    return res;
}

void dump_idStorage(){
    static u8 buf[512];
    int fd = k_tbl->KernelIOOpen("ms0:/idStorage.bin", PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
    
    for (int i=0; i<0x140; i++){
        dcIdStorageReadLeaf(i, buf);
        k_tbl->KernelIOWrite(fd, buf, 512);
    }
    k_tbl->KernelIOClose(fd);
}

int kthread(SceSize args, void *argp){

    pspDebugScreenPrintf("Dumping ipl.bin\n");
    NandLock(0);
	int res = pspIplGetIpl(orig_ipl);
	NandUnlock();

    int fd = k_tbl->KernelIOOpen("ms0:/ipl.bin", PSP_O_WRONLY|PSP_O_CREAT|PSP_O_TRUNC, 0777);
    k_tbl->KernelIOWrite(fd, orig_ipl, sizeof(orig_ipl));
    k_tbl->KernelIOClose(fd);

    pspDebugScreenPrintf("Dumping idStorage\n");
    dump_idStorage();

    open_flash();

    pspDebugScreenPrintf("Dumping flash0\n");
    copy_folder_recursive("flash0:/", "ms0:/flash0");
    pspDebugScreenPrintf("Flash0 Dumped\n");

    pspDebugScreenPrintf("Dumping flash3\n");
    copy_folder_recursive("flash3:/", "ms0:/flash3");
    pspDebugScreenPrintf("Flash3 Dumped\n");

    k_tbl->KernelExitThread(0);

    return 0;
}

void initDumperKernelThread(){

    BufferCopyWithRange = FindFunction("sceMemlmd", "semaphore", 0x4C537C72);

    if (BufferCopyWithRange == NULL){
        pspDebugScreenPrintf("ERROR: cannot find import BufferCopyWithRange\n");
        return;
    }

    NandLock = FindFunction("sceLowIO_Driver", "sceNand_driver", 0xAE4438C7);
    NandUnlock = FindFunction("sceLowIO_Driver", "sceNand_driver", 0x41FFA822);
    NandReadPagesRawAll = FindFunction("sceLowIO_Driver", "sceNand_driver", 0xC478C1DE);
    NandReadBlockWithRetry = FindFunction("sceLowIO_Driver", "sceNand_driver", 0xC32EA051);

    if (!NandLock || !NandUnlock || !NandReadPagesRawAll || !NandReadBlockWithRetry){
        pspDebugScreenPrintf("ERROR: cannot find sceNand imports\n");
        pspDebugScreenPrintf("%p, %p, %p, %p\n", NandLock, NandUnlock, NandReadPagesRawAll, NandReadBlockWithRetry);
        return;
    }

    KernelGetUserLevel = FindFunction("sceThreadManager", "ThreadManForKernel", 0xF6427665);
    IdStorageReadLeaf = FindFunction("sceIdStorage_Service", "sceIdStorage_driver", 0xEB00C509);
    
    if (IdStorageReadLeaf == NULL){
        pspDebugScreenPrintf("ERROR: cannot find import IdStorageReadLeaf\n");
        return;
    }

    if (KernelGetUserLevel == NULL){
        pspDebugScreenPrintf("ERROR: cannot find import KernelGetUserLevel\n");
        return;
    }

    SceUID kthreadID = k_tbl->KernelCreateThread( "arkflasher", (void*)KERNELIFY(&kthread), 1, 0x20000, PSP_THREAD_ATTR_VFPU, NULL);
    if (kthreadID >= 0){
        // start thread and wait for it to end
        k_tbl->KernelStartThread(kthreadID, 0, NULL);
        k_tbl->waitThreadEnd(kthreadID, NULL);
        k_tbl->KernelDeleteThread(kthreadID);
    }
}