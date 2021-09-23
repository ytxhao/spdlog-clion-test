//
// Created by yuhao on 2021/4/6.
//

#ifndef SPDLOGTEST_SPD_AES_H
#define SPDLOGTEST_SPD_AES_H

namespace ams {
    class spd_aes {
    public:
        static std::string key;
        static unsigned char start_code[];
        static unsigned char end_code[];
        static unsigned char continue_buff[];
        static int get_aes_encrypt_len(int in_size);
        static bool ecb_encrypt(unsigned char *in, int in_size, unsigned char *out , int out_len, unsigned char *key, int key_len);
        static int ecb_decrypt(unsigned char *in, int in_size, unsigned char *out, int out_size,unsigned char *key, int key_len);
        static int unpack(unsigned char *input, int input_len, unsigned char *output, int output_len);
        static int pack(unsigned char *input, int input_len, unsigned char *output, int output_len);
    };
}

#endif //SPDLOGTEST_SPD_AES_H
