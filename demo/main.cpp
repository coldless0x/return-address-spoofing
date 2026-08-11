#include "spoof/api.hpp"
#include "spoof/gadget.hpp"
#include "spoof/hook.hpp"
#include "spoof/log.hpp"
#include "spoof/pe.hpp"

#include <Windows.h>
#include <psapi.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct ModuleOwnership {
    std::string name;
    std::size_t rva = 0;
    bool known = false;
};

ModuleOwnership ResolveOwner(const void* address) {
    const auto target = reinterpret_cast<std::uintptr_t>(address);

    DWORD needed = 0;
    EnumProcessModulesEx(GetCurrentProcess(), nullptr, 0, &needed, LIST_MODULES_ALL);
    if (needed == 0) {
        return {};
    }

    std::vector<HMODULE> modules(needed / sizeof(HMODULE));
    if (!EnumProcessModulesEx(GetCurrentProcess(), modules.data(), needed, &needed, LIST_MODULES_ALL)) {
        return {};
    }

    for (const HMODULE module : modules) {
        MODULEINFO info{};
        if (!GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info))) {
            continue;
        }
        const auto base = reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll);
        if (target >= base && target < base + info.SizeOfImage) {
            char name[MAX_PATH]{};
            GetModuleBaseNameA(GetCurrentProcess(), module, name, MAX_PATH);
            return {std::string(name), target - base, true};
        }
    }

    return {};
}

__declspec(noinline) std::uintptr_t ProbeTarget(std::uintptr_t tag, std::uintptr_t a, std::uintptr_t b, std::uintptr_t c) {
    const auto observed_ret = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    const auto ret_slot = reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress());
    const auto owner = ResolveOwner(reinterpret_cast<const void*>(observed_ret));

    LOG_INFO("ret slot 0x%llX -> %s+0x%llX",
             static_cast<unsigned long long>(ret_slot),
             owner.known ? owner.name.c_str() : "?",
             static_cast<unsigned long long>(owner.rva));

    return tag + a + b + c;
}

using FnProbe = std::uintptr_t (*)(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t);

void WaitForEnter(const char* message) {
    std::printf("[+] %s ", message);
    std::fflush(stdout);
    int c = 0;
    while ((c = std::fgetc(stdin)) != '\n' && c != EOF) {
    }
    std::printf("\n");
    std::fflush(stdout);
}

void RunControlRun(const FnProbe fn) {
    const auto result = fn(0x10, 0x20, 0x40, 0x80);
    LOG_INFO("control result 0x%llX", static_cast<unsigned long long>(result));
}

void RunSpoofedRun(spf::Spoofer& spoofer, const FnProbe fn) {
    const auto result = spoofer.Call(fn, (std::uintptr_t)0x10, (std::uintptr_t)0x20, (std::uintptr_t)0x40, (std::uintptr_t)0x80);
    LOG_INFO("spoofed result 0x%llX", static_cast<unsigned long long>(result));
}

void RunStackSanity() {
    void* frames[16]{};
    const auto count = RtlCaptureStackBackTrace(0, static_cast<DWORD>(std::size(frames)), frames, nullptr);
    LOG_INFO("stack %u frames", static_cast<unsigned>(count));
}

void PrintUsage() {
    LOG_INFO("usage: demo [--no-color] [--no-pause] [--level <level>] [--module <dll>] [--messagebox] [--gadgets <n>]");
}

int RunGadgetListing(std::wstring_view module_name, std::size_t count) {
    HMODULE module = GetModuleHandleW(std::wstring(module_name).c_str());
    if (!module) {
        module = LoadLibraryW(std::wstring(module_name).c_str());
    }
    if (!module) {
        LOG_ERROR("module '%ls' not loadable", std::wstring(module_name).c_str());
        return 1;
    }

    const auto view = spf::ModuleView::Open(module);
    if (!view) {
        LOG_ERROR("module '%ls' unreadable", std::wstring(module_name).c_str());
        return 1;
    }

    constexpr std::uint8_t kJmpRbx[] = {0xFF, 0x23};
    spf::Scanner scanner({0x00});
    const auto gadgets = scanner.FindAll(*view, kJmpRbx, count);

    LOG_INFO("module '%ls': %zu JMP [RBX] gadgets listed", std::wstring(module_name).c_str(), gadgets.size());
    for (const auto& gadget : gadgets) {
        LOG_INFO("  gadget 0x%llX (rva 0x%llX, section '%s', offset 0x%llX)",
                 static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(gadget.address)),
                 static_cast<unsigned long long>(gadget.rva),
                 std::string(gadget.section_name).c_str(),
                 static_cast<unsigned long long>(gadget.section_offset));
    }

    return gadgets.empty() ? 1 : 0;
}

using FnMessageBox = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
FnMessageBox g_original_msgbox = nullptr;

int WINAPI HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    static spf::Spoofer s_spoofer(L"wininet.dll");
    if (!s_spoofer.Ready() || !g_original_msgbox) {
        LOG_ERROR("spoofer unavailable, abort");
        return -1;
    }

    const int result = static_cast<int>(s_spoofer.Call(g_original_msgbox, hWnd, lpText, lpCaption, uType));
    LOG_INFO("dispatch done, return path restored");
    return result;
}

int RunMessageBoxDemo() {
    spf::IatHook hook;
    if (!hook.Install("USER32.dll", "MessageBoxA", reinterpret_cast<const void*>(&HookedMessageBox))) {
        LOG_ERROR("IAT hook install failed for USER32.dll!MessageBoxA");
        return 2;
    }

    g_original_msgbox = reinterpret_cast<FnMessageBox>(const_cast<void*>(hook.Original()));

    LOG_INFO("IAT patched: MessageBoxA -> HookedMessageBox (thunk 0x%llX, original 0x%llX)",
             static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(hook.Thunk())),
             static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(g_original_msgbox)));
    LOG_INFO("calling MessageBoxA through the spoofed dispatch");

    const int result = MessageBoxA(nullptr, "this call was dispatched through a spoofed return address", "spoof", MB_OK);
    LOG_INFO("MessageBoxA returned %d", result);

    hook.Restore();
    LOG_INFO("hook restored");
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    spf::LogInit({});

    std::wstring module_name = L"wininet.dll";
    std::size_t gadget_count = 0;
    bool do_messagebox = false;
    bool no_pause = false;

    const auto parse_level = [&](const wchar_t* text) -> bool {
        const std::wstring level(text);
        if (level == L"trace") { spf::LogLevel(spf::Level::Trace); return true; }
        if (level == L"debug") { spf::LogLevel(spf::Level::Debug); return true; }
        if (level == L"info")  { spf::LogLevel(spf::Level::Info);  return true; }
        if (level == L"warn")  { spf::LogLevel(spf::Level::Warn);  return true; }
        if (level == L"error") { spf::LogLevel(spf::Level::Error); return true; }
        return false;
    };

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg(argv[i]);
        if (arg == L"--no-color") {
            spf::LogColor(false);
        } else if (arg == L"--no-pause") {
            no_pause = true;
        } else if (arg == L"--level" && i + 1 < argc) {
            if (!parse_level(argv[++i])) {
                LOG_ERROR("unknown level '%ls'", argv[i]);
                PrintUsage();
                return 1;
            }
        } else if (arg == L"--module" && i + 1 < argc) {
            module_name = argv[++i];
        } else if (arg == L"--messagebox") {
            do_messagebox = true;
        } else if (arg == L"--gadgets" && i + 1 < argc) {
            gadget_count = _wtoi(argv[++i]);
        } else if (arg == L"--help" || arg == L"-h") {
            PrintUsage();
            return 0;
        } else {
            LOG_ERROR("unknown argument '%ls'", arg.c_str());
            PrintUsage();
            return 1;
        }
    }

    if (gadget_count > 0) {
        return RunGadgetListing(module_name, gadget_count);
    }

    spf::Spoofer spoofer(module_name);
    if (!spoofer.Ready()) {
        LOG_ERROR("no JMP [RBX] gadget available");
        return 1;
    }

    const FnProbe probe = &ProbeTarget;

    const auto own_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const auto host_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(std::wstring(spoofer.SpoofModule()).c_str()));

    LOG_INFO("spoof v1.0.0 (x64)");
    LOG_INFO("image  demo.exe   0x%llX", static_cast<unsigned long long>(own_base));
    LOG_INFO("host   %ls          0x%llX",
             std::wstring(spoofer.SpoofModule()).c_str(),
             static_cast<unsigned long long>(host_base));
    LOG_INFO("gadget %ls+0x%llX = 0x%llX (JMP [RBX])",
             std::wstring(spoofer.SpoofModule()).c_str(),
             static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(spoofer.Gadget()) - host_base),
             static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(spoofer.Gadget())));
    LOG_INFO("target ProbeTarget        +0x%llX",
             static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(probe) - own_base));

    LOG_INFO("[BEFORE] ret slot -> demo.exe");
    RunControlRun(probe);

    if (!no_pause) {
        WaitForEnter("[BEFORE] ENTER to run spoofed call");
    }

    RunSpoofedRun(spoofer, probe);
    RunStackSanity();

    LOG_INFO("[AFTER] ret slot -> %ls+0x%llX = 0x%llX",
             std::wstring(spoofer.SpoofModule()).c_str(),
             static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(spoofer.Gadget()) - host_base),
             static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(spoofer.Gadget())));

    if (do_messagebox) {
        return RunMessageBoxDemo();
    }

    if (!no_pause) {
        WaitForEnter("[AFTER] ENTER to exit");
    }
    return 0;
}