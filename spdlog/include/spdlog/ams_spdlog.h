//
// Created by yuhao on 3/18/21.
//

#ifndef ANDROID_MEDIA_STREAM_AMS_SPDLOG_H
#define ANDROID_MEDIA_STREAM_AMS_SPDLOG_H

#include <spdlog/spdlog.h>
//#ifndef AMS_SPDLOG_LOGGER
//#define AMS_SPDLOG_LOGGER
std::string to_hex_string(const uint8_t* buf, int len, const std::string& separator = ":");
void spdlog_reset_av_print_last_time();
void spdlog_normal_print(spdlog::level::level_enum l, const char* tag, const char* fmt, ...);
void spdlog_audio_print(spdlog::level::level_enum l, const char* tag, const char* fmt, ...);
void spdlog_video_print(spdlog::level::level_enum l, const char* tag, const char* fmt, ...);
void init_spdlog(const std::string &file, bool encrypt);
void deinit_spdlog();

#define SPDLOGI(TAG, fmt, ...) spdlog_normal_print(spdlog::level::level_enum::info, TAG, fmt, ##__VA_ARGS__)
#define SPDLOGD(TAG, fmt, ...) spdlog_normal_print(spdlog::level::level_enum::debug, TAG, fmt, ##__VA_ARGS__)
#define SPDLOGW(TAG, fmt, ...) spdlog_normal_print(spdlog::level::level_enum::warn, TAG, fmt, ##__VA_ARGS__)
#define SPDLOGE(TAG, fmt, ...) spdlog_normal_print(spdlog::level::level_enum::err, TAG, fmt, ##__VA_ARGS__)

#define SPDLOGAI(TAG, fmt, ...) spdlog_audio_print(spdlog::level::level_enum::info, TAG, fmt, ##__VA_ARGS__)
#define SPDLOGAD(TAG, fmt, ...) spdlog_audio_print(spdlog::level::level_enum::debug, TAG, fmt, ##__VA_ARGS__)
#define SPDLOGAW(TAG, fmt, ...) spdlog_audio_print(spdlog::level::level_enum::warn, TAG, fmt, ##__VA_ARGS__)
#define SPDLOGAE(TAG, fmt, ...) spdlog_audio_print(spdlog::level::level_enum::err, TAG, fmt, ##__VA_ARGS__)

#define SPDLOGVI(TAG, fmt, ...) spdlog_video_print(spdlog::level::level_enum::info, TAG, fmt, ##__VA_ARGS__)
#define SPDLOGVD(TAG, fmt, ...) spdlog_video_print(spdlog::level::level_enum::debug, TAG, fmt, ##__VA_ARGS__)
#define SPDLOGVW(TAG, fmt, ...) spdlog_video_print(spdlog::level::level_enum::warn, TAG, fmt, ##__VA_ARGS__)
#define SPDLOGVE(TAG, fmt, ...) spdlog_video_print(spdlog::level::level_enum::err, TAG, fmt, ##__VA_ARGS__)

//#endif

#endif //ANDROID_MEDIA_STREAM_AMS_SPDLOG_H
