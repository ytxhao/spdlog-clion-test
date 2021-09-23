//
// Created by yuhao on 3/30/21.
//

#include <openssl/aes.h>
#include "AES2.h"
#include "Padding2.h"
unsigned char start_code[] = {0x00,0x00,0x01};
unsigned char end_code[] = {0x00,0x00,0x02};
int start_code_len = 3;
int end_code_len = 3;
namespace ams {
    namespace openssl {

        bool AES2::ecb_encryptv2(unsigned char *in, int in_size, unsigned char **out , int  *out_len, unsigned char *key, int key_len, bool enc) {
            assert(key_len == 16 || key_len == 24 || key_len == 32);
            if (enc) {
                // 生成加密key
                AES_KEY aes_key;
                if (AES_set_encrypt_key(key, key_len * 8, &aes_key) != 0) {
                    return false;
                }
                // 数据开头和结尾分别使用"000001"和"000002"作为分隔符，同时因为字符串是以'0'结尾所以要多加一位
                auto *inTemp = (unsigned char *)malloc(in_size + 6 +1);
//                char *inTemp = new char [in_size + 6];
                unsigned char start[] = {0x00,0x00,0x01};
                unsigned char end[] = {0x00,0x00,0x02};
                memcpy(inTemp, start, 3);
                memcpy(inTemp + 3, in, in_size);
                memcpy(inTemp + 3 + in_size + 1, end, 3);

                // 进行PKCS7Padding填充
                unsigned int remainder = (in_size + 7) % AES_BLOCK_SIZE;
                unsigned int paddingSize = (remainder == 0) ? AES_BLOCK_SIZE : (AES_BLOCK_SIZE - remainder);

                int paddingTempLen = in_size + 6 + 1 + paddingSize;
                auto *inPaddingTemp = (unsigned char *)malloc(paddingTempLen);
                auto *outPaddingTemp = (unsigned char *)malloc(paddingTempLen);
                memcpy(inPaddingTemp, inTemp, in_size + 6 +1);
                memset(inPaddingTemp + (in_size + 6 +1), paddingTempLen, paddingTempLen);


                for (int i = 0; i < paddingTempLen / AES_BLOCK_SIZE; i++)
                {
                    AES_ecb_encrypt((const unsigned char*)inPaddingTemp + AES_BLOCK_SIZE * i,
                                    (unsigned char*)outPaddingTemp + AES_BLOCK_SIZE * i,
                                    &aes_key,
                                    AES_ENCRYPT);
                }
                *out_len = paddingTempLen;
                *out = outPaddingTemp;
                return true;
            } else {
                // 生成解密key
                AES_KEY aes_key;
                if (AES_set_decrypt_key((const unsigned char*)key, key_len * 8, &aes_key) != 0)
                {
                    return false;
                }
                auto *outTemp = (unsigned char *)malloc(in_size);
                memset(outTemp,0xff,in_size);
                for (int i = 0; i < in_size / AES_BLOCK_SIZE; i++)
                {
                    AES_ecb_encrypt((const unsigned char*)in + AES_BLOCK_SIZE * i,
                                    (unsigned char*)outTemp + AES_BLOCK_SIZE * i,
                                    &aes_key,
                                    AES_DECRYPT);
                }
                *out = outTemp;
            }
            return true;
        }
        /**
         * @brief AES::ecb_encrypt
         * ECB模式加解密，填充模式采用PKCS7Padding，
         * 支持对任意长度明文进行加解密。
         * @param in 输入数据
         * @param out 输出结果
         * @param key 密钥，长度必须是16/24/32字节，否则加密失败
         * @param enc true-加密，false-解密
         * @return 执行结果
         */
        bool AES2::ecb_encrypt(const std::string &in, std::string &out,
                                            const std::string &key,
                                            bool enc) {
            assert(key.size() == 16 || key.size() == 24 || key.size() == 32);
            if (enc) {
                // 生成加密key
                AES_KEY aes_key;
                if (AES_set_encrypt_key((const unsigned char*)key.data(), key.size() * 8, &aes_key) != 0)
                {
                    return false;
                }

                // 进行PKCS7Padding填充
                std::string inTemp = Padding2::PKCS7Padding(in, AES_BLOCK_SIZE);

                // 执行ECB模式加密
                out.resize(inTemp.size()); // 调整输出buf大小
                for (int i = 0; i < inTemp.size() / AES_BLOCK_SIZE; i++)
                {
                    AES_ecb_encrypt((const unsigned char*)inTemp.data() + AES_BLOCK_SIZE * i,
                                    (unsigned char*)out.data() + AES_BLOCK_SIZE * i,
                                    &aes_key,
                                    AES_ENCRYPT);
                }
                return true;
            } else {
                // 生成解密key
                AES_KEY aes_key;
                if (AES_set_decrypt_key((const unsigned char*)key.data(), key.size() * 8, &aes_key) != 0)
                {
                    return false;
                }

                // 执行ECB模式解密
                out.resize(in.size()); // 调整输出buf大小
                for (int i = 0; i < in.size() / AES_BLOCK_SIZE; i++)
                {
                    AES_ecb_encrypt((const unsigned char*)in.data() + AES_BLOCK_SIZE * i,
                                    (unsigned char*)out.data() + AES_BLOCK_SIZE * i,
                                    &aes_key,
                                    AES_DECRYPT);
                }

                // 解除PKCS7Padding填充
                out = Padding2::PKCS7UnPadding(out);
                return true;
            }
        }

        int AES2::get_aes_encrypt_len(int in_size) {
//            int ret = 0;
            // 数据开头和结尾分别使用"000001"和"000002"作为分隔符
            int pack_size = start_code_len + in_size + end_code_len;

            // 进行PKCS7Padding填充
            int remainder = (pack_size) % AES_BLOCK_SIZE;
            int paddingSize = (remainder == 0) ? AES_BLOCK_SIZE : (AES_BLOCK_SIZE - remainder);

            int encrypt_len = pack_size + paddingSize;
            return encrypt_len;
        }

        int AES2::get_aes_encrypt_lenv3(int in_size) {
            return 0;
        }

        bool AES2::ecb_encryptv3(unsigned char *in, int in_size, unsigned char *out , int out_len, unsigned char *key, int key_len) {
            assert(key_len == 16 || key_len == 24 || key_len == 32);
            // 生成加密key
            AES_KEY aes_key;
            if (AES_set_encrypt_key(key, key_len * 8, &aes_key) != 0) {
                return false;
            }
            memcpy(out, start_code, start_code_len);
            memcpy(out + start_code_len , in, in_size);
            memcpy(out  + in_size + end_code_len, end_code, end_code_len);
//            int encrypt_len = get_aes_encrypt_len(in_size);
            for (int i = 0; i < out_len / AES_BLOCK_SIZE; i++)
            {
                AES_ecb_encrypt((const unsigned char*)out + AES_BLOCK_SIZE * i,
                                (unsigned char*)out + AES_BLOCK_SIZE * i,
                                &aes_key,
                                AES_ENCRYPT);
            }
            return true;
        }

        int AES2::ecb_decryptv3(unsigned char *in, int in_size, unsigned char *key, int key_len) {
            assert(key_len == 16 || key_len == 24 || key_len == 32);
            // 生成解密key
            AES_KEY aes_key;
            if (AES_set_decrypt_key((const unsigned char*)key, key_len * 8, &aes_key) != 0)
            {
                return -1;
            }
            auto *outTemp = (unsigned char *)malloc(in_size);
            for (int i = 0; i < in_size / AES_BLOCK_SIZE; i++)
            {
                AES_ecb_encrypt((const unsigned char*)in + AES_BLOCK_SIZE * i,
                                (unsigned char*)outTemp + AES_BLOCK_SIZE * i,
                                &aes_key,
                                AES_DECRYPT);
            }

            int data_len = unpack(outTemp,in_size,in,in_size);

            if (outTemp != nullptr) {
                free(outTemp);
                outTemp = nullptr;
            }
            return data_len;
        }

        unsigned char tmp_code[] = {0x00,0x00,0x00,0x00,0x00,0x00};
        int tmp_code_len = 0;
        int AES2::unpack(unsigned char *input, int input_len, unsigned char *output, int output_len) {
//            std::cout << "sizeof(tmp_code):" << sizeof(tmp_code) << std::endl;
            bool find_start_code = false;
            bool find_end_code = false;
            int output_index = 0;
            int output_size = 0;
            int start_code_index = -1;
            int end_code_index = -1;
            int start_code_count = 0;
            int end_code_count = 0;
            int new_input_len = input_len + sizeof(tmp_code);
            auto * new_input_buff = (unsigned char *)malloc(new_input_len);
            memset(new_input_buff,0,new_input_len);
            memcpy(new_input_buff, tmp_code, sizeof(tmp_code));
            memcpy(new_input_buff + sizeof(tmp_code), input, input_len);

            // 查找起始码
            for (int i =0;i < new_input_len;i++) {
                if (new_input_buff[i] == start_code[0] && new_input_buff[i+1] == start_code[1] && new_input_buff[i+2] == start_code[2]) {
                    find_start_code = true;
                    start_code_index = i;
                    start_code_count++;
                }

                if (new_input_buff[i] == end_code[0] && new_input_buff[i+1] == end_code[1] && new_input_buff[i+2] == end_code[2]) {
                    find_end_code = true;
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
                memcpy(tmp_code, start_code, sizeof(start_code));
                memcpy(tmp_code + sizeof(start_code), new_input_buff + new_input_len - 3 , 3);
            } else {
                memset(tmp_code,0, sizeof(tmp_code));
            }

            if (new_input_buff != nullptr) {
                free(new_input_buff);
                new_input_buff = nullptr;
            }
            return output_size;
        }

        int AES2::addStartCode(unsigned char *data, int capacity, int size) {
            if (capacity - size > 7) {
                unsigned char *tmp_buff = static_cast<unsigned char *>(malloc(capacity));
                if (tmp_buff != nullptr) {
                    memset(tmp_buff, 0, capacity);
                    memcpy(tmp_buff, start_code, start_code_len);
                    memcpy(tmp_buff + start_code_len, data, size);
                    memcpy(tmp_buff + start_code_len + size + 1, end_code, end_code_len);
                    memcpy(data, tmp_buff, capacity);
                    free(tmp_buff);
                    tmp_buff = nullptr;
                    return 0;
                }else {
                    return -1;
                }
            } else {
                return -1;
            }

        }

//        unsigned char tmp_code[] = {0x00,0x00,0x00};
//        int tmp_code_len = 0;
//        int AES2::unpack(unsigned char *input, int input_len, unsigned char *output, int output_len) {
//            int output_index = 0;
//            bool find_start_code = false;
//            for(int i = 0; i < input_len; i++) {
//                // input len < 3
//                if (input_len < 3) {
//                    tmp_code[i] = input[i];
//                    tmp_code_len = input_len;
//                    return input_len;
//                } else if (input_len >= 3) {
//                    // 对比起始码，如果匹配成功则将后面的数据写入 output，知道遇见结束符
//                    if (input[i] == start_code[0] && input[i+1] == start_code[1] && input[i+2] == start_code[2]) {
//                        // 找到了起始码
//                        find_start_code = true;
//                    }
//
//                    if (find_start_code) {
//                        // 除去起始码后剩余的buf长度
//                        int remain_len = input_len - i;
//                        if (remain_len > 0 && remain_len <= 3) {
//                            tmp_code_len = remain_len;
//                            tmp_code[0] = input[i];
//                        }
//                    }
//                }
//
//
//
//                if ( i + 2 >= input_len - 1) {
//                    tmp_code[0] = input[i];
//                    tmp_code[1] = input[i+1];
//                    tmp_code[2] = input[i+2];
//                    return i + 1 ;
//                }
//                if (input[i] == start_code[0] && input[i+1] == start_code[1] && input[i+2] == start_code[2]) {
//                   i = i + 3;
//                }
//
//                if () {
//
//                }
//                if (input[i] == end_code[0] && input[i+1] == end_code[1] && input[i+2] == end_code[2]) {
//                    break;
//                }
//                output[output_index] = input[i];
//                output_index++ ;
//
//            }
//            return 0;
//        }

    }
}