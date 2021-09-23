//
// Created by yuhao on 3/30/21.
//

#include "Padding2.h"

namespace ams {

    namespace openssl {
        /**
         * @brief Padding::getPKCS7PaddedLength
         * 根据原始数据长度，计算进行PKCS7填充后的数据长度
         * @param dataLen 原始数据长度
         * @param alignSize 对齐字节数
         * @return 返回填充后的数据长度
         */
        int Padding2::GetPKCS7PaddedLength(int dataLen, int alignSize) {
            // 计算填充的字节数（按alignSize字节对齐进行填充）
            int remainder = dataLen % alignSize;
            int paddingSize = (remainder == 0) ? alignSize : (alignSize - remainder);
            return (dataLen + paddingSize);
        }

        /**
         * @brief Padding::PKCS7Padding
         * 采用PKCS7Padding方式，将in数据进行alignSize字节对齐填充。
         * 此函数用于加密前，对明文进行填充。
         * @param in 数据
         * @param alignSize 对齐字节数
         * @return 返回填充后的数据
         */
        std::string Padding2::PKCS7Padding(const std::string &in, int alignSize) {
            // 计算需要填充字节数（按alignSize字节对齐进行填充）
            int in_len = in.length();
            unsigned int remainder = in_len % alignSize;
            unsigned int paddingSize = (remainder == 0) ? alignSize : (alignSize - remainder);

            // 进行填充
            std::string temp(in);
            temp.append(paddingSize, paddingSize);
            return temp;
        }

        /**
         * @brief Padding::PKCS7UnPadding
         * 采用PKCS7Padding方式，将in数据去除填充。
         * 此函数用于解密后，对解密结果进一步去除填充，以得到原始数据。
         * @param in 数据
         * @return 返回去除填充后的数据
         */
        std::string Padding2::PKCS7UnPadding(const std::string &in) {
            char paddingSize = in.at(in.size() - 1);
            return in.substr(0,in.size() - paddingSize);
        }

    }
}