#pragma once

#include <cstdint>
#include <string_view>

namespace spf {

class IatHook {
public:
    IatHook() = default;
    ~IatHook();
    IatHook(const IatHook&) = delete;
    IatHook& operator=(const IatHook&) = delete;
    IatHook(IatHook&& other) noexcept;
    IatHook& operator=(IatHook&& other) noexcept;

    [[nodiscard]] bool Install(std::string_view module, std::string_view function, const void* replacement);
    [[nodiscard]] bool Installed() const noexcept;
    void Restore() noexcept;

    [[nodiscard]] const void* Original() const noexcept;
    [[nodiscard]] void** Thunk() const noexcept;

private:
    void* original_ = nullptr;
    const void* replacement_ = nullptr;
    void** thunk_ = nullptr;
};

} // namespace spf