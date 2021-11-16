//
// Created by yuhao on 3/18/21.
//

#include <spdlog/ams_spdlog.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/details/os.h>
#include <spdlog/sinks/stdout_color_sinks.h>
//#include <spdlog/sinks/android_sink.h>
#define TAG "AMSSpdlog"

#define LOG_BUF_SIZE 1024
#define LOG_WRITE_AV_DURATION 3

static bool isInit = false;
static std::shared_ptr<spdlog::logger> audio_logger = nullptr;
static std::shared_ptr<spdlog::logger> video_logger = nullptr;
static long long audio_logger_last_time = 0;
static long long video_logger_last_time = 0;
void init_spdlog(const std::string &path, bool encrypt) {
    if (isInit) {
        return;
    }
    spdlog::set_level(spdlog::level::debug);
    std::string normal_file;
    if (encrypt) {
        normal_file = path + "/normal/ams_normal_rotating.enc";
    } else {
        normal_file = path + "/normal/ams_normal_rotating.log";
    }
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(normal_file, 1024 * 1024 * 5, 3, encrypt);
    file_sink->set_pattern("%Y-%m-%d %H:%M:%S.%e %P-%t %L/%v");

//    auto android_sink = std::make_shared<spdlog::sinks::android_sink_mt>("", true);
//    android_sink->set_pattern("%v");

    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(spdlog::level::debug);
    console_sink->set_pattern("%Y-%m-%d %H:%M:%S.%e %P-%t %L/%v");

    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(file_sink);
    sinks.push_back(console_sink);
//    sinks.push_back(android_sink);

    auto combined_logger = std::make_shared<spdlog::logger>( "multi_sink", begin( sinks ), end( sinks ));
    spdlog::set_default_logger(combined_logger);

    std::chrono::seconds s(3);
    spdlog::flush_every(s);

    spdlog_reset_av_print_last_time();
    std::string audio_file = path + "/av/ams_audio_rotating.txt";
    audio_logger = spdlog::rotating_logger_mt("audio_logger", audio_file, 1024 * 1024 * 5, 3 , true);
    audio_logger->set_pattern("%Y-%m-%d %H:%M:%S.%e %P-%t %L/%v");

    std::string video_file = path + "/av/ams_video_rotating.txt";
    video_logger = spdlog::rotating_logger_mt("video_logger", video_file, 1024 * 1024 * 5, 3, true);
    video_logger->set_pattern("%Y-%m-%d %H:%M:%S.%e %P-%t %L/%v");

    isInit = true;
    SPDLOGD(TAG, "init_spdlog");
    SPDLOGW(TAG, "init_spdlog");
    SPDLOGE(TAG, "init_spdlog");
    SPDLOGI(TAG, "init_spdlog path:%s", path.c_str());
}

void deinit_spdlog() {
    if (isInit) {
        SPDLOGI(TAG, "deinit_spdlog");
        spdlog::drop_all();
    }
}

void spdlog_normal_print(spdlog::level::level_enum l, const char* tag, const char* fmt, ...) {
    if (isInit) {
        va_list ap;
        char buf[LOG_BUF_SIZE];

        va_start(ap, fmt);
        vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
        va_end(ap);
        if (l == spdlog::level::level_enum::info) {
            spdlog::info("{}: {}", tag, buf);
        } else if (l == spdlog::level::level_enum::debug) {
            spdlog::debug("{}: {}", tag, buf);
        } else if (l == spdlog::level::level_enum::warn) {
            spdlog::warn("{}: {}", tag, buf);
        } else if (l == spdlog::level::level_enum::err) {
            spdlog::error("{}: {}", tag, buf);
        }
    }
}

void spdlog_reset_av_print_last_time() {
    audio_logger_last_time = 0;
    video_logger_last_time = 0;
}

void spdlog_audio_print(spdlog::level::level_enum l, const char* tag, const char* fmt, ...) {
    if (isInit) {
        spdlog::log_clock::time_point time_point_now = spdlog::details::os::now();
        spdlog::log_clock::duration duration_since_epoch = time_point_now.time_since_epoch();
        long long current_time_seconds = std::chrono::duration_cast<std::chrono::seconds>(duration_since_epoch).count();
        if (current_time_seconds - audio_logger_last_time <= LOG_WRITE_AV_DURATION) {
            return;
        }
        audio_logger_last_time = current_time_seconds;

        va_list ap;
        char buf[LOG_BUF_SIZE];

        va_start(ap, fmt);
        vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
        va_end(ap);
        if (l == spdlog::level::level_enum::info) {
            audio_logger->info("{}: {}", tag, buf);
        } else if (l == spdlog::level::level_enum::debug) {
            audio_logger->debug("{}: {}", tag, buf);
        } else if (l == spdlog::level::level_enum::warn) {
            audio_logger->warn("{}: {}", tag, buf);
        } else if (l == spdlog::level::level_enum::err) {
            audio_logger->error("{}: {}", tag, buf);
        }
    }
}

void spdlog_video_print(spdlog::level::level_enum l, const char* tag, const char* fmt, ...) {
    if (isInit) {
        spdlog::log_clock::time_point time_point_now = spdlog::details::os::now();
        spdlog::log_clock::duration duration_since_epoch = time_point_now.time_since_epoch();
        long long current_time_seconds = std::chrono::duration_cast<std::chrono::seconds>(duration_since_epoch).count();
        if (current_time_seconds - video_logger_last_time <= LOG_WRITE_AV_DURATION) {
            return;
        }
        video_logger_last_time = current_time_seconds;

        va_list ap;
        char buf[LOG_BUF_SIZE];

        va_start(ap, fmt);
        vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
        va_end(ap);
        if (l == spdlog::level::level_enum::info) {
            video_logger->info("{}: {}", tag, buf);
        } else if (l == spdlog::level::level_enum::debug) {
            video_logger->debug("{}: {}", tag, buf);
        } else if (l == spdlog::level::level_enum::warn) {
            video_logger->warn("{}: {}", tag, buf);
        } else if (l == spdlog::level::level_enum::err) {
            video_logger->error("{}: {}", tag, buf);
        }
    }
}

std::string to_hex_string(const uint8_t* buf, int len, const std::string& separator)
{
    std::string output;
    char temp[8];
    for (int i = 0; i < len; ++i)
    {
        sprintf(temp,"0x%.2x",(uint8_t)buf[i]);
        output.append(temp,4);
        output.append(separator);
    }

    return output;
}