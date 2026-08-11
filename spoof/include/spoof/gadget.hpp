#pragma once

#include "spoof/pe.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace spf {

struct GadgetInfo {
    const void* address = nullptr;
    std::size_t section_offset = 0;
    std::size_t rva = 0;
    std::string_view section_name;
    std::uint32_t characteristics = 0;
};

class Scanner {
public:
    explicit Scanner(std::vector<std::uint8_t> banned = {0x00});

    [[nodiscard]] std::optional<GadgetInfo> FindFirst(const ModuleView& module, std::span<const std::uint8_t> pattern) const;
    [[nodiscard]] std::vector<GadgetInfo> FindAll(const ModuleView& module, std::span<const std::uint8_t> pattern, std::size_t limit) const;

private:
    [[nodiscard]] bool BytesAllowed(std::span<const std::uint8_t> bytes) const;

    std::vector<std::uint8_t> banned_;
};

} // namespace spf