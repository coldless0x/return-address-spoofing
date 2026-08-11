#include "spoof/gadget.hpp"

#include <algorithm>

namespace spf {

Scanner::Scanner(std::vector<std::uint8_t> banned)
    : banned_(std::move(banned)) {}

bool Scanner::BytesAllowed(std::span<const std::uint8_t> bytes) const {
    return std::none_of(banned_.begin(), banned_.end(), [bytes](std::uint8_t banned) {
        return std::any_of(bytes.begin(), bytes.end(), [banned](std::uint8_t b) { return b == banned; });
    });
}

std::optional<GadgetInfo> Scanner::FindFirst(const ModuleView& module, std::span<const std::uint8_t> pattern) const {
    auto all = FindAll(module, pattern, 1);
    if (all.empty()) {
        return std::nullopt;
    }
    return all.front();
}

std::vector<GadgetInfo> Scanner::FindAll(const ModuleView& module, std::span<const std::uint8_t> pattern, std::size_t limit) const {
    std::vector<GadgetInfo> results;
    if (pattern.empty() || !module.IsLoaded()) {
        return results;
    }

    const auto image_base = reinterpret_cast<std::uintptr_t>(module.base);

    for (const auto& section : module.sections) {
        if (!section.Executable()) {
            continue;
        }

        const auto* begin = section.start;
        const auto* end = section.start + section.size;

        const auto* cursor = begin;
        while (cursor < end) {
            const auto it = std::search(cursor, end, pattern.begin(), pattern.end());
            if (it == end) {
                break;
            }

            const auto candidate = std::span<const std::uint8_t>(it, it + pattern.size());
            if (BytesAllowed(candidate)) {
                GadgetInfo info{};
                info.address = it;
                info.section_offset = static_cast<std::size_t>(it - begin);
                info.rva = static_cast<std::size_t>(reinterpret_cast<std::uintptr_t>(it) - image_base);
                info.section_name = section.name;
                info.characteristics = section.characteristics;
                results.push_back(info);
                if (results.size() >= limit) {
                    return results;
                }
            }

            cursor = it + 1;
        }
    }

    return results;
}

} // namespace spf