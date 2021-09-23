//
// Created by yuhao on 3/30/21.
//

#ifndef SPDLOG_AND_CRASH_COLLECT_PADDING2_H
#define SPDLOG_AND_CRASH_COLLECT_PADDING2_H
#include <iostream>
#include <string>
namespace ams {

    namespace openssl {

        class Padding2 {
        public:
            static int GetPKCS7PaddedLength(int dataLen, int alignSize);
            static std::string PKCS7Padding(const std::string &in, int alignSize);
            static std::string PKCS7UnPadding(const std::string &in);

        };
    }
}

#endif //SPDLOG_AND_CRASH_COLLECT_PADDING_H
