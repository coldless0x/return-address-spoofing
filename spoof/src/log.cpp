#include "spoof/log.hpp"

#include <Windows.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace spf {
namespace {

constexpr WORD kColors[] = {
    FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    FOREGROUND_RED | FOREGROUND_INTENSITY,
};

std::atomic<Level> g_level{Level::Info};
std::atomic<bool> g_color{true};
std::mutex g_mutex;
bool g_supported = false;

char Tag(Level level) {
    switch (level) {
        case Level::Warn:  return '!';
        case Level::Error: return '-';
        default:           return '+';
    }
}

void One(Level level, const char* fmt, va_list args) {
    char msg[1024]{};
    vsnprintf(msg, sizeof(msg) - 1, fmt, args);

    std::lock_guard<std::mutex> lock(g_mutex);

    const HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    const bool color = g_supported && g_color.load();

    if (color) {
        SetConsoleTextAttribute(console, kColors[static_cast<std::uint8_t>(level)]);
    }
    std::printf("[%c] %s\n", Tag(level), msg);
    if (color) {
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
}

} // namespace

void LogInit(const LogOpts& opts) {
    g_level.store(opts.level);
    g_color.store(opts.color);

    const HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    g_supported = console != INVALID_HANDLE_VALUE && GetConsoleMode(console, &mode);
}

void LogLevel(Level level) {
    g_level.store(level);
}

void LogColor(bool enabled) {
    g_color.store(enabled);
}

void LogWrite(Level level, const char* fmt, ...) {
    if (level < g_level.load()) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    One(level, fmt, args);
    va_end(args);
}

} // namespace spf