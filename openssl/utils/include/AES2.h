//
// Created by yuhao on 3/30/21.
//

#ifndef SPDLOG_AND_CRASH_COLLECT_AES2_H
#define SPDLOG_AND_CRASH_COLLECT_AES2_H
#include <iostream>
#include <string>

extern unsigned char start_code[];
extern unsigned char end_code[];
extern int start_code_len;
extern int end_code_len;

namespace ams {
    namespace openssl {
        class AES2 {

        public:
            bool ecb_encrypt(const std::string &in, std::string &out, const std::string &key, bool enc);
            static bool ecb_encryptv2(unsigned char *in, int in_size, unsigned char **out , int  *out_len, unsigned char *key, int key_len, bool enc);
            static int get_aes_encrypt_len(int in_size);
            static int get_aes_encrypt_lenv3(int in_size);
            static bool ecb_encryptv3(unsigned char *in, int in_size, unsigned char *out , int out_len, unsigned char *key, int key_len);
            static int ecb_decryptv3(unsigned char *in, int in_size, unsigned char *key, int key_len);

            static int unpack(unsigned char *input, int input_len, unsigned char *output, int output_len);
            static int addStartCode(unsigned char *data, int capacity, int size);
        };
    }
}

#endif //SPDLOG_AND_CRASH_COLLECT_AES_H
