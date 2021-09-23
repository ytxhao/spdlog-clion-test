//
// Created by yuhao on 2021/4/6.
//

#include <openssl/aes.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cassert>
#include "spd_aes.h"

namespace ams {
    std::string spd_aes::key = std::string("8ca72b05705d5c46f412af8cbedz5aa6");
    unsigned char spd_aes::start_code[] = {0x00, 0x00, 0x01};
    unsigned char spd_aes::end_code[] = {0x00, 0x00, 0x02};
    unsigned char spd_aes::continue_buff[] = {0x00,0x00,0x00,0x00,0x00,0x00};
    int spd_aes::get_aes_encrypt_len(int in_size) {
        // 数据开头和结尾分别使用"000001"和"000002"作为分隔符
//        int pack_size = start_code_len + in_size + end_code_len;
        int pack_size = sizeof(start_code) + in_size + sizeof(end_code);

        // 进行PKCS7Padding填充
        int remainder = (pack_size) % AES_BLOCK_SIZE;
        int paddingSize = (remainder == 0) ? AES_BLOCK_SIZE : (AES_BLOCK_SIZE - remainder);

        int encrypt_len = pack_size + paddingSize;
        return encrypt_len;
    }

    bool spd_aes::ecb_encrypt(unsigned char *in, int in_size, unsigned char *out, int out_len, unsigned char *key,
                              int key_len) {
        assert(key_len == 16 || key_len == 24 || key_len == 32);
        assert(get_aes_encrypt_len(in_size) == out_len);
        // 生成加密key
        AES_KEY aes_key;
        if (AES_set_encrypt_key(key, key_len * 8, &aes_key) != 0) {
            return false;
        }
        memset(out, 0, out_len);
        pack(in, in_size, out, out_len);
//        memcpy(out, start_code, sizeof(start_code));
//        memcpy(out + sizeof(start_code), in, in_size);
//        memcpy(out + sizeof(start_code) + in_size, end_code, sizeof(end_code));

        for (int i = 0; i < out_len / AES_BLOCK_SIZE; i++)
        {
            AES_ecb_encrypt((const unsigned char*)out + AES_BLOCK_SIZE * i,
                            (unsigned char*)out + AES_BLOCK_SIZE * i,
                            &aes_key,
                            AES_ENCRYPT);
        }
        return true;
    }

    int spd_aes::ecb_decrypt(unsigned char *in, int in_size, unsigned char *out, int out_size,unsigned char *key, int key_len) {
        assert(key_len == 16 || key_len == 24 || key_len == 32);
        assert(in_size == out_size);
        // 生成解密key
        AES_KEY aes_key;
        if (AES_set_decrypt_key((const unsigned char*)key, key_len * 8, &aes_key) != 0)
        {
            return -1;
        }
        auto *outTemp = (unsigned char *)malloc(out_size);
        memset(outTemp, 0, out_size);
        for (int i = 0; i < out_size / AES_BLOCK_SIZE; i++)
        {
            AES_ecb_encrypt((const unsigned char*)in + AES_BLOCK_SIZE * i,
                            (unsigned char*)outTemp + AES_BLOCK_SIZE * i,
                            &aes_key,
                            AES_DECRYPT);
        }

        int data_len = unpack(outTemp, in_size, out, out_size);

        if (outTemp != nullptr) {
            free(outTemp);
            outTemp = nullptr;
        }
        return data_len;
    }

    int spd_aes::unpack(unsigned char *input, int input_len, unsigned char *output, int output_len) {
        int output_size = 0;
        int start_code_index = -1;
        int end_code_index = -1;
        int start_code_count = 0;
        int end_code_count = 0;
        int new_input_len = input_len + sizeof(continue_buff);
        auto * new_input_buff = (unsigned char *)malloc(new_input_len);
        memset(output,0, output_len);
        memset(new_input_buff,0, new_input_len);
        memcpy(new_input_buff, continue_buff, sizeof(continue_buff));
        memcpy(new_input_buff + sizeof(continue_buff), input, input_len);

        // 查找起始码
        for (int i =0;i < new_input_len - 2;i++) {
            if (new_input_buff[i] == start_code[0] && new_input_buff[i+1] == start_code[1] && new_input_buff[i+2] == start_code[2]) {
                start_code_index = i;
                start_code_count++;
            }

            if (new_input_buff[i] == end_code[0] && new_input_buff[i+1] == end_code[1] && new_input_buff[i+2] == end_code[2]) {
                end_code_index = i;
                end_code_count++;
            }

            if (start_code_index < end_code_index) {
                //拷贝起始码和结束码之间的数据
                memcpy(output + output_size,new_input_buff + start_code_index + sizeof(start_code), end_code_index - start_code_index - sizeof(start_code));
                output_size = end_code_index - start_code_index - sizeof(start_code);
                // 完成一次拷贝清除起始码和结束码下标
                start_code_index = 0;
                end_code_index = 0;
            }
        }

        // 最后一个 end code 没有找到
        if (start_code_count > end_code_count) {
            int cpy_len = new_input_len - (start_code_index + sizeof(start_code)) - 3;
            memcpy(output + output_size,new_input_buff + start_code_index + sizeof(start_code), cpy_len);
            output_size = output_size + cpy_len;
            memcpy(continue_buff, start_code, sizeof(start_code));
            memcpy(continue_buff + sizeof(start_code), new_input_buff + new_input_len - 3 , 3);
        } else {
            memset(continue_buff,0, sizeof(continue_buff));
        }

        if (new_input_buff != nullptr) {
            free(new_input_buff);
            new_input_buff = nullptr;
        }
        return output_size;
    }

    int spd_aes::pack(unsigned char *input, int input_len, unsigned char *output, int output_len) {
        memset(output, 0, output_len);
        memcpy(output, start_code, sizeof(start_code));
        memcpy(output + sizeof(start_code), input, input_len);
        memcpy(output + sizeof(start_code) + input_len, end_code, sizeof(end_code));
        return 0;
    }
}