#pragma once

#include <Windows.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace spf {

struct Section {
    std::string name;
    const std::uint8_t* start = nullptr;
    std::size_t size = 0;
    std::uint32_t characteristics = 0;

    [[nodiscard]] bool Executable() const noexcept;
};

struct ModuleView {
    HMODULE base = nullptr;
    std::size_t image_size = 0;
    std::wstring path;
    std::string name;
    std::vector<Section> sections;

    [[nodiscard]] bool IsLoaded() const noexcept;

    static std::optional<ModuleView> Open(HMODULE module);
};

struct ImportedFunction {
    void** thunk_slot = nullptr;
    void* original = nullptr;
    std::string name;
    std::uint16_t ordinal_hint = 0;
    bool import_by_name = false;
};

std::optional<std::span<const ImportedFunction>> EnumerateImports(std::string_view module_name, ModuleView& out_module);

} // namespace spf