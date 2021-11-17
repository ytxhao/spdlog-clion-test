#ifndef ZORRO_XOR_H_
#define ZORRO_XOR_H_

#include <iostream>

namespace zorro {
// 数据头包含4字节的起始码，和四字节的加密数据长度
extern unsigned char data_header[8];

int xor_encrypt(char* data, size_t bytes);
int xor_decrypt(char* data, size_t bytes);
int xor_encrypt(const char* in, char* out, uint32_t bytes);
int xor_decrypt(const char* in, char* out, uint32_t bytes);

#if 0
int xor_encrypt(const uint32_t *in, uint32_t* out, size_t key_start_pos, bool reverse_key_order);
int xor_decrypt(const uint32_t *in, uint32_t* out, size_t key_start_pos, bool reverse_key_order);
#endif

} // zorro

#endif // ZORRO_XOR_H_ 
