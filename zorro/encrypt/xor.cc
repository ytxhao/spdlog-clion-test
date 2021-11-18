#include "xor.h"
// #include "rtc_base/logging.h"

namespace zorro {

unsigned char key[128] = {
        0xD6, 0x71, 0x3F, 0xC0, 0x65, 0x87, 0xD5, 0x8B, 0x56, 0x3C, 0x6E, 0xF9, 0xED, 0xAD, 0x24, 0x92,
        0x70, 0xFC, 0x96, 0x10, 0x89, 0x9C, 0xFA, 0x45, 0xB6, 0x52, 0xB,  0xCD, 0x6C, 0xF6, 0x18, 0x3A,
        0xC0, 0xBD, 0xBF, 0x5C, 0x6C, 0x3E, 0xD3, 0xCE, 0xAD, 0xEB, 0x7A, 0x2,  0x37, 0x93, 0x12, 0x6F,
        0x99, 0xE0, 0x9A, 0xF9, 0x28, 0xC6, 0xB2, 0x8E, 0x1B, 0xBE, 0x7E, 0xCD, 0x6C, 0xEC, 0xED, 0xA5,
        0xD6, 0x71, 0x3F, 0xC0, 0x65, 0x87, 0xD5, 0x8B, 0x56, 0x3C, 0x6E, 0xF9, 0xED, 0xAD, 0x24, 0x92,
        0x70, 0xFC, 0x96, 0x10, 0x89, 0x9C, 0xFA, 0x45, 0xB6, 0x52, 0xB,  0xCD, 0x6C, 0xF6, 0x18, 0x3A,
        0xC0, 0xBD, 0xBF, 0x5C, 0x6C, 0x3E, 0xD3, 0xCE, 0xAD, 0xEB, 0x7A, 0x2,  0x37, 0x93, 0x12, 0x6F,
        0x99, 0xE0, 0x9A, 0xF9, 0x28, 0xC6, 0xB2, 0x8E, 0x1B, 0xBE, 0x7E, 0xCD, 0x6C, 0xEC, 0xED, 0xA5,
};

// 数据头包含4字节的起始码，和四字节的加密数据长度
unsigned char data_header[8] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};

int xor_encrypt(char* data, size_t bytes) {
    if (data && bytes > 0) {
        size_t key_len = sizeof(key);
        for (size_t i = 0; i < bytes / key_len + 1; ++i) {
            for (size_t j = 0; j < key_len && j < bytes - i * key_len; ++j) {
                data[i * key_len  + j] ^= key[j];
            }
        }
        return bytes;
    }

    return -1;
}

int xor_decrypt(char* data, size_t bytes) {
    return xor_encrypt(data, bytes);
}

int xor_encrypt_data_wrap(const char* in, size_t in_len, char* out, size_t out_len) {
    size_t header_len = sizeof(data_header);
    if (in_len +  header_len <= out_len) {
        memcpy(out, data_header, header_len);
        memcpy(out + 4, &in_len, 4);
        memcpy(out + header_len, in, in_len);
        return in_len +  header_len;
    } else {
        return -1;
    }

}

int xor_encrypt(const char* in, char* out, size_t bytes) {
    if (in && out && bytes > 0) {
        size_t key_len = sizeof(key);
        for (size_t i = 0; i < bytes / key_len + 1; ++i) {
            for (size_t j = 0; j < key_len && j < bytes - i * key_len; ++j) {
                out[i * key_len  + j] = in[i * key_len  + j] ^ key[j];
            }
        }
        return bytes;
    }
    return -1;
}

int xor_decrypt(const char* in, char* out, size_t bytes) {
    return xor_encrypt(in, out, bytes);
}

#if 0
int xor_encrypt(const uint32_t *in, uint32_t* out, size_t key_start_pos, bool reverse_key_order) {
  if (in && out) {
    for (size_t i = 0; i < sizeof(*in); ++i) {
      if (reverse_key_order) {
        ((char*)out)[i] = ((char*)in)[i] ^ key[key_start_pos + sizeof(*in) - i - 1];
      } else {
        ((char*)out)[i] = ((char*)in)[i] ^ key[key_start_pos + i];
      }
    }
    return sizeof(*in);
  }
  return -1;
}

int xor_decrypt(const uint32_t *in, uint32_t* out, size_t key_start_pos, bool reverse) {
  return xor_encrypt(in, out, key_start_pos, reverse);
}
#endif

} // zorro

