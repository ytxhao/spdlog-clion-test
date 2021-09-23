//
// Created by yuhao on 3/30/21.
//

#ifndef SPDLOG_AND_CRASH_COLLECT_AES_H
#define SPDLOG_AND_CRASH_COLLECT_AES_H
#include <iostream>
#include <string>
namespace ams {
    namespace openssl {
        class AES {

        public:
            bool ecb_encrypt(const std::string &in, std::string &out, const std::string &key, bool enc);
            bool cbc_encrypt(const std::string &in, std::string &out, const std::string &key,const std::string &ivec, bool enc);
            bool cfb1_encrypt(const std::string &in, std::string &out, const std::string &key,const std::string &ivec, bool enc);
            bool cfb8_encrypt(const std::string &in, std::string &out, const std::string &key,const std::string &ivec, bool enc);
            bool cfb128_encrypt(const std::string &in, std::string &out, const std::string &key,const std::string &ivec, bool enc);
            bool ofb128_encrypt(const std::string &in, std::string &out, const std::string &key,const std::string &ivec, bool enc);
        };
    }
}

#endif //SPDLOG_AND_CRASH_COLLECT_AES_H
