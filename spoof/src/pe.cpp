#define NOMINMAX
#include <Windows.h>
#include <psapi.h>

#include "spoof/pe.hpp"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <mutex>

namespace spf {
namespace {

struct ImportCache {
    std::wstring module_name;
    ModuleView view;
    std::vector<ImportedFunction> functions;
};

std::mutex g_mutex;
std::vector<ImportCache> g_cache;

bool ValidDos(const std::uint8_t* base) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    return dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0;
}

std::uint8_t* RvaPtr(const std::uint8_t* base, std::uint32_t rva) {
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    for (std::size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto* section = IMAGE_FIRST_SECTION(nt) + i;
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
            return const_cast<std::uint8_t*>(base) + section->PointerToRawData + (rva - section->VirtualAddress);
        }
    }
    return nullptr;
}

} // namespace

bool Section::Executable() const noexcept {
    return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

bool ModuleView::IsLoaded() const noexcept {
    return base != nullptr;
}

std::optional<ModuleView> ModuleView::Open(HMODULE module) {
    if (!module) {
        return std::nullopt;
    }

    ModuleView view;
    view.base = module;

    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info)) || !info.lpBaseOfDll) {
        return std::nullopt;
    }

    view.image_size = info.SizeOfImage;

    wchar_t path_buffer[MAX_PATH]{};
    if (GetModuleFileNameW(module, path_buffer, MAX_PATH) > 0) {
        view.path = path_buffer;
        const auto pos = view.path.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            const std::wstring file = view.path.substr(pos + 1);
            char ansi[MAX_PATH]{};
            WideCharToMultiByte(CP_ACP, 0, file.c_str(), -1, ansi, MAX_PATH, nullptr, nullptr);
            view.name = ansi;
        }
    }

    const auto* base = reinterpret_cast<const std::uint8_t*>(module);
    if (!ValidDos(base)) {
        return std::nullopt;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    for (std::size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto* section = IMAGE_FIRST_SECTION(nt) + i;
        Section s{};
        s.name = std::string(reinterpret_cast<const char*>(section->Name), strnlen(reinterpret_cast<const char*>(section->Name), 8));
        s.start = base + section->VirtualAddress;
        s.size = std::max(section->Misc.VirtualSize, section->SizeOfRawData);
        s.characteristics = section->Characteristics;
        view.sections.push_back(std::move(s));
    }

    return view;
}

std::optional<std::span<const ImportedFunction>> EnumerateImports(std::string_view module_name, ModuleView& out_module) {
    std::lock_guard<std::mutex> lock(g_mutex);

    const std::wstring wide_name(module_name.begin(), module_name.end());

    for (const auto& entry : g_cache) {
        if (_wcsicmp(entry.module_name.c_str(), wide_name.c_str()) == 0) {
            out_module = entry.view;
            return std::span<const ImportedFunction>(entry.functions);
        }
    }

    ImportCache cache;
    cache.module_name = wide_name;

    const auto* own_base = reinterpret_cast<const std::uint8_t*>(GetModuleHandleW(nullptr));
    if (!own_base || !ValidDos(own_base)) {
        return std::nullopt;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(own_base + reinterpret_cast<const IMAGE_DOS_HEADER*>(own_base)->e_lfanew);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) {
        return std::nullopt;
    }

    const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(RvaPtr(own_base, dir.VirtualAddress));
    if (!descriptor) {
        return std::nullopt;
    }

    while (descriptor->Name != 0) {
        const auto* dll_name = reinterpret_cast<const char*>(RvaPtr(own_base, descriptor->Name));
        if (dll_name && _stricmp(dll_name, module_name.data()) == 0) {
            const auto* original_thunk = descriptor->OriginalFirstThunk
                                             ? reinterpret_cast<const IMAGE_THUNK_DATA*>(RvaPtr(own_base, descriptor->OriginalFirstThunk))
                                             : nullptr;
            auto* first_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(RvaPtr(own_base, descriptor->FirstThunk));
            if (!first_thunk) {
                return std::nullopt;
            }

            if (const auto module_view = ModuleView::Open(LoadLibraryW(wide_name.c_str()))) {
                cache.view = *module_view;
            }
            if (!cache.view.IsLoaded()) {
                return std::nullopt;
            }

            std::size_t index = 0;
            while (true) {
                const auto thunk_value = original_thunk ? original_thunk->u1.AddressOfData : 0;
                if (first_thunk[index].u1.Function == 0) {
                    break;
                }

                ImportedFunction fn{};
                fn.thunk_slot = reinterpret_cast<void**>(&first_thunk[index].u1.Function);
                fn.original = reinterpret_cast<void*>(first_thunk[index].u1.Function);

                if (thunk_value != 0 && !(thunk_value & IMAGE_ORDINAL_FLAG)) {
                    const auto* by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(RvaPtr(own_base, static_cast<std::uint32_t>(thunk_value)));
                    if (by_name) {
                        fn.ordinal_hint = by_name->Hint;
                        fn.name.assign(reinterpret_cast<const char*>(by_name->Name));
                        fn.import_by_name = true;
                    }
                }

                cache.functions.push_back(fn);
                ++index;
            }

            g_cache.push_back(std::move(cache));
            auto& stored = g_cache.back();
            out_module = stored.view;
            return std::span<const ImportedFunction>(stored.functions);
        }
        ++descriptor;
    }

    return std::nullopt;
}

} // namespace spf