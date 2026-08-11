#pragma once

#include <cstdint>
#include <string_view>

namespace spf {

enum class Level : std::uint8_t { Trace, Debug, Info, Warn, Error, Off };

struct LogOpts {
    bool color = true;
    Level level = Level::Info;
};

void LogInit(const LogOpts& opts = {});
void LogLevel(Level level);
void LogColor(bool enabled);
void LogWrite(Level level, const char* fmt, ...);

} // namespace spf

#define LOG_TRACE(...) ::spf::LogWrite(::spf::Level::Trace, __VA_ARGS__)
#define LOG_DEBUG(...) ::spf::LogWrite(::spf::Level::Debug, __VA_ARGS__)
#define LOG_INFO(...)  ::spf::LogWrite(::spf::Level::Info,  __VA_ARGS__)
#define LOG_WARN(...)  ::spf::LogWrite(::spf::Level::Warn,  __VA_ARGS__)
#define LOG_ERROR(...) ::spf::LogWrite(::spf::Level::Error, __VA_ARGS__)