#include <iostream>
#include <chrono>
#include <thread>
#include <cstring>
#include <cassert>
//#include <direct.h>
#include <queue>
#include <vector>
#include <list>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/include/spdlog/ams_spdlog.h>
#include <spdlog/include/spdlog/details/os.h>

#include <openssl/utils/include/AES.h>
#include <openssl/utils/include/AES2.h>
#include <openssl/utils/include/spd_aes.h>
#include <zconf.h>
#include "xor.h"

#define BLOCK_SIZE 16
//
#define TAG "spdlog-test"

#define MAXLEN 4096

int main(int argc, char *argv[]) {
    std::string output_file_path;
    if (argc < 2) {
        std::cout<<"missing parameter!"<<std::endl;
        return -1;
    }

    std::string input_file_path(argv[1]);

    FILE * in_file = fopen(input_file_path.c_str(), "rb");
    if (in_file == nullptr)
    {
        fprintf(stderr, "Value of errno: %d\n", errno);
        fprintf(stderr, "Error opening input file: %s\n", strerror(errno));
        return -1;
    }

    if (argc > 2) {
        output_file_path.append(argv[2]);
        std::cout << "Output file path: " << output_file_path << std::endl;
    } else {
        size_t pos = input_file_path.find_last_of('.');
        if (pos == std::string::npos) {
            fprintf(stderr, "Input file name error!\n");
            return -1;
        } else {
            output_file_path = input_file_path.substr(0,pos + 1) + "dec";
            std::cout << "Output file path: " << output_file_path << std::endl;
        }
    }

    FILE * out_file = fopen(output_file_path.c_str(), "wb");
    if (out_file == nullptr) {
        fprintf(stderr, "Value of errno: %d\n", errno);
        fprintf(stderr, "Error opening output file: %s\n", strerror(errno));
        return -1;
    }

    char read_buf[MAXLEN] = {0};
    char header_buf[8] = {0};
    int index = 0;
    while(fread(read_buf, 1, 1, in_file) != 0)
    {
        header_buf[index] = read_buf[0];
        if (index >= 3) {
            if (header_buf[0] == 0x00 && header_buf[1] == 0x00 && header_buf[2] == 0x00 && header_buf[3] == 0x01) {
                index = 0;
                uint32_t real_encrypt_len = 0;
                fread(read_buf, 1, 4, in_file);
                memcpy(&real_encrypt_len, read_buf , 4);
                memset(read_buf, 0 , MAXLEN);
                fread(read_buf, 1, real_encrypt_len, in_file);
                zorro::xor_decrypt(read_buf, read_buf, real_encrypt_len);
                fwrite(read_buf, 1, real_encrypt_len, out_file);
                memset(read_buf, 0 , MAXLEN);
            } else {
                memmove(header_buf, header_buf + 1 , 3);
            }
        } else {
            index++;
        }
    }
    fclose(in_file);
    fclose(out_file);
    return 0;
}

int main_xor_encrypt(int argc, char *argv[]) {
    std::string *log_path;
    char *buffer;
    if((buffer = getcwd(nullptr,0)) == nullptr){
        perror("getcwd error");
    } else {
        printf("%s\n", buffer);
        log_path = new std::string(buffer);
        init_spdlog(*log_path, true);
        free(buffer);
    }
    SPDLOGI(TAG,"ABCDEFG1234567");

    SPDLOGI(TAG,"0123456789"
                "0123456789"
                "0123456789"
                "0123456789"
                "0123456789"
                "0123456789");
    SPDLOGI(TAG,"yyyyyyyy");
    FILE * outfile, *infile;
    std::string outfile_path;
    outfile_path = *log_path + "/normal/ams_normal_rotating.dec";
    outfile = fopen(outfile_path.c_str(), "wb" );
    std::string infile_path = *log_path + "/normal/ams_normal_rotating.enc";
    infile = fopen(infile_path.c_str(), "rb");
    char buf[MAXLEN];
    char header_buf[MAXLEN];
    size_t rc;
    int index = 0;
    while( (rc = fread(buf, 1, 1, infile)) != 0 )
    {
        header_buf[index] = buf[0];
        if (index >= 3) {
            if (header_buf[0] == 0x00 && header_buf[1] == 0x00 && header_buf[2] == 0x00 && header_buf[3] == 0x01) {
                index = 0;
                uint32_t real_encrypt_len = 0;
                fread(buf, 1, 4, infile);
                memcpy(&real_encrypt_len, buf , 4);
                std::cout << "--------------------real_encrypt_len:"<<real_encrypt_len<<std::endl;
                memset(buf, 0 , MAXLEN);
                fread(buf, 1, real_encrypt_len, infile);
                zorro::xor_decrypt(buf, buf, real_encrypt_len);
                std::cout << "---------------------buf:"<<buf;
                memset(buf, 0 , MAXLEN);
            } else {
                memmove(header_buf, header_buf + 1 , 3);
            }
        } else {
            index++;
        }

    }
    fclose(infile);
    fclose(outfile);
    return 0;
}

int main8(int argc, char *argv[]) {

//    for(int i=0;i < argc;i++)
//    {
//        std::cout<<"argument["<<i<<"] is: "<< argv[i]<<std::endl;
//
//    }
    std::string output_file_path;
    if (argc < 2) {
        std::cout<<"missing parameter!"<<std::endl;
        return -1;
    }

    std::string input_file_path(argv[1]);

    FILE * in_file = fopen(input_file_path.c_str(), "rb");
    if (in_file == nullptr)
    {
        fprintf(stderr, "Value of errno: %d\n", errno);
        fprintf(stderr, "Error opening input file: %s\n", strerror(errno));
        return -1;
    }

    if (argc > 2) {
        output_file_path.append(argv[2]);
        std::cout << "Output file path: " << output_file_path << std::endl;
    } else {
        int pos = input_file_path.find_last_of('.');
        if (pos == std::string::npos) {
            fprintf(stderr, "Input file name error!\n");
            return -1;
        } else {
            output_file_path = input_file_path.substr(0,pos + 1) + "dec";
            std::cout << "Output file path: " << output_file_path << std::endl;
        }
    }

    FILE * out_file = fopen(output_file_path.c_str(), "wb");
    if (out_file == nullptr) {
        fprintf(stderr, "Value of errno: %d\n", errno);
        fprintf(stderr, "Error opening output file: %s\n", strerror(errno));
        return -1;
    }
    char dec_buf[MAXLEN] = {0};
    char read_buf[MAXLEN];
    int read_count = 0;
    while( (read_count = fread(read_buf, 1, BLOCK_SIZE * 5, in_file)) != 0 )
    {
        int dec_len = ams::spd_aes::ecb_decrypt((unsigned char *)read_buf,read_count, (unsigned char *)dec_buf, read_count,(unsigned char *) ams::spd_aes::key.c_str(), ams::spd_aes::key.length());
        fwrite(dec_buf, 1,dec_len, out_file);
    }
    fclose(in_file);
    fclose(out_file);
    return 0;
}

int main9(int argc,char *argv[]) {

    std::string *log_path;
    char *buffer;
    if((buffer = getcwd(nullptr,0)) == nullptr){
        perror("getcwd error");
    } else {
        printf("%s\n", buffer);
        log_path = new std::string(buffer);
        init_spdlog(*log_path, true);
        free(buffer);
    }

    SPDLOGI(TAG,"0123456789");
    FILE * outfile, *infile;
    std::string outfile_path;
    outfile_path = *log_path + "/normal/ams_normal_rotating.dec";
    outfile = fopen(outfile_path.c_str(), "wb" );
    std::string infile_path = *log_path + "/normal/ams_normal_rotating.enc";
    infile = fopen(infile_path.c_str(), "rb");
    char buf[MAXLEN];
    int rc;
    std::string key = std::string("8cc72b05705d5c46f412af8cbed55aad");
    ams::openssl::AES aes;
    ams::openssl::AES2 aes2;
    std::string input("hello world!\n") ;

    unsigned char test_data_input1[] = {0x00,0x00,0x01,0x30,0x31,0x32,0x32,0x32,0x38,0x00};
    int test_data_input_len = sizeof(test_data_input1);
    int test_data_out_len = test_data_input_len * 5;
    unsigned char *test_data_output = (unsigned char *)malloc(test_data_out_len);
    memset(test_data_output,0,test_data_out_len);


    aes2.unpack(test_data_input1,test_data_input_len,test_data_output,test_data_out_len);
//    std::cout << "test_data_output:"<< test_data_output << std::endl;
    SPDLOGI(TAG,"test_data_output:%s",test_data_output);
    unsigned char test_data_input2[] = {0x00,0x02,0x33,0x33,0x33,0x00,0x00,0x01,0x34,0x00,0x00,0x02};
    int test_data_input_len2 = sizeof(test_data_input2);
    memset(test_data_output,0,test_data_out_len);
    aes2.unpack(test_data_input2,test_data_input_len2,test_data_output,test_data_out_len);

//    std::cout << "test_data_output:"<< test_data_output << std::endl;
    SPDLOGI(TAG,"test_data_output:%s",test_data_output);
//    std::cout << "sizeof(unsigned char):"<< sizeof(unsigned char) << std::endl;
    SPDLOGI(TAG,"sizeof(unsigned char):%d",sizeof(unsigned char));
    char dec_buf[MAXLEN] = {0};
    while( (rc = fread(buf, 1, BLOCK_SIZE * 5, infile)) != 0 )
    {

//        int dec_len = aes2.ecb_decryptv3((unsigned char *)(buf), rc, (unsigned char *) key.c_str(), key.length());
        int dec_len = ams::spd_aes::ecb_decrypt((unsigned char *)buf,rc, (unsigned char *)dec_buf, rc,(unsigned char *) ams::spd_aes::key.c_str(), ams::spd_aes::key.length());
        fwrite(dec_buf, 1,dec_len, outfile);
    }
    fclose(infile);
    fclose(outfile);

    return 1;
}
int main10(int argc,char *argv[]) {
    const  char * chtest = std::string("aaaaaaa").c_str();
    std::cout << "Hello, World!" << std::endl;
    spdlog::info("Welcome to spdlog version {}.{}.{}  !", SPDLOG_VER_MAJOR, SPDLOG_VER_MINOR, SPDLOG_VER_PATCH);
    std::string fsink("ams_rotating_sink.txt");
    std::string flogger("ams_rotating_logger.txt");
    spdlog::set_level(spdlog::level::debug); // Set global log level to debug
    // spdlog::set_pattern("%Y-%m-%d %H:%M:%S.%e %t %L: %v"); // change log pattern
    spdlog::set_pattern("%Y-%m-%d %H:%M:%S.%e %P-%t %L: %v"); // change log pattern
    std::string path1("/a/b/c");
    path1.append("/d/e/f/txt.txt");
    std::string tag = "spdlog-android";
//    auto android_logger = spdlog::android_logger_mt("android", tag);
    auto file_logger = spdlog::rotating_logger_mt("ams_file_logger", flogger, 1024 * 1024 * 5, 3,true);

    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(fsink,1024 * 1024 * 5,3,true);
    file_sink->set_pattern("%Y-%m-%d %H:%M:%S.%e %P-%t %L: %v");
    file_sink->set_level(spdlog::level::debug);

    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_pattern("%Y-%m-%d %H:%M:%S.%e %P-%t %L/%v");
    console_sink->set_level(spdlog::level::debug);
//    auto android_sink = std::make_shared<spdlog::sinks::android_sink_mt>(tag);
//    android_sink->set_pattern("%v");
//    android_sink->set_level(spdlog::level::debug);

    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(file_sink);
    sinks.push_back(console_sink);
//    sinks.push_back(android_sink);
    auto combined_logger = std::make_shared<spdlog::logger>( "multi_sink", begin( sinks ), end( sinks ));
//    spdlog::register_logger( combined_logger );
    spdlog::set_default_logger(combined_logger);
    std::chrono::seconds s(3);
    spdlog::flush_every(s);




    char str_tst[] = "    123";

    for (int i = 0; i < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        spdlog::info("{} stringFromJNI path: {}",TAG,chtest);
//        std::string test(str_tst == nullptr ? "str_tst == nullptr" : str_tst);
        std::string str_save_output(false ? "" : str_tst);
//        str_save_output =  spdlog::cfg::helpers::trim_(str_save_output);
        spdlog::info("{} stringFromJNI test {}",TAG,str_save_output);
//        spdlog::debug("{} stringFromJNI path: {}",TAG,i);
//        spdlog::warn("{} stringFromJNI path: {}",TAG,i);
//        spdlog::error("{} stringFromJNI path: {}",TAG,i);
//        SPDLOGI(TAG, "stringFromJNI path: {}",i);
    }

    spdlog::log_clock::time_point time_point_now = spdlog::details::os::now();

    spdlog::log_clock::duration duration_since_epoch = time_point_now.time_since_epoch();
    std::time_t tt;
    tt = spdlog::log_clock::to_time_t (time_point_now);
    long long seconds_since_epoch = std::chrono::duration_cast<std::chrono::seconds>(duration_since_epoch).count(); // 将时长转换为微秒数
    std::cout << "today is: " << ctime(&tt);
    std::cout << "seconds_since_epoch is: " << seconds_since_epoch << std::endl;

//    system_clock::time_point time_point_now = system_clock::now(); // 获取当前时间点
//    system_clock::duration duration_since_epoch
//            = time_point_now.time_since_epoch(); // 从1970-01-01 00:00:00到当前时间点的时长
//    time_t microseconds_since_epoch
//            = duration_cast<microseconds>(duration_since_epoch).count(); // 将时长转换为微秒数
//    time_t seconds_since_epoch = microseconds_since_epoch / 1000000; // 将时长转换为秒数
//    std::tm current_time = *std::localtime(&seconds_since_epoch); // 获取当前时间（精确到秒）
//    time_t tm_microsec = microseconds_since_epoch % 1000; // 当前时间的微妙数
//    time_t tm_millisec = microseconds_since_epoch / 1000 % 1000; // 当前时间的毫秒数


//    tt = spdlog::log_clock::to_time_t ( tomorrow );
//    std::cout << "tomorrow will be: " << ctime(&tt);

    file_logger->info("main out:{}",path1);

    std::string tmp("2021-03-31 17:57:19.278 15316-15316 I/MainActivityJNI:    12 nativeOnClick 34     \n");
    const char *a12 = tmp.c_str();
    const char *a13  = tmp.data();
    SPDLOGI(TAG, "main out :{}",tmp.length());


//    std::this_thread::sleep_for(std::chrono::milliseconds(8000));
    return 0;
}


