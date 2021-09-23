//
// Created by yuhao on 3/30/21.
//

#include <openssl/aes.h>
#include "AES.h"
#include "Padding.h"
#include <cassert>
namespace ams {
    namespace openssl {
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
        bool AES::ecb_encrypt(const std::string &in, std::string &out,
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
                std::string inTemp = Padding::PKCS7Padding(in, AES_BLOCK_SIZE);

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
                out = Padding::PKCS7UnPadding(out);
                return true;
            }
        }

        bool AES::cbc_encrypt(const std::string &in, std::string &out, const std::string &key,
                              const std::string &ivec, bool enc) {
            return false;
        }

        bool AES::cfb1_encrypt(const std::string &in, std::string &out, const std::string &key,
                               const std::string &ivec, bool enc) {
            return false;
        }

        bool AES::cfb8_encrypt(const std::string &in, std::string &out, const std::string &key,
                               const std::string &ivec, bool enc) {
            return false;
        }

        bool AES::cfb128_encrypt(const std::string &in, std::string &out, const std::string &key,
                                 const std::string &ivec, bool enc) {
            return false;
        }

        bool AES::ofb128_encrypt(const std::string &in, std::string &out, const std::string &key,
                                 const std::string &ivec, bool enc) {
            return false;
        }

    }
}