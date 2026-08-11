#include "spoof/hook.hpp"

#include <Windows.h>

#include "spoof/pe.hpp"

#include <utility>

namespace spf {

static void MakeWritable(void* page) {
    DWORD old = 0;
    VirtualProtect(page, sizeof(void*), PAGE_READWRITE, &old);
}

IatHook::~IatHook() {
    Restore();
}

IatHook::IatHook(IatHook&& other) noexcept
    : original_(std::exchange(other.original_, nullptr)),
      replacement_(std::exchange(other.replacement_, nullptr)),
      thunk_(std::exchange(other.thunk_, nullptr)) {}

IatHook& IatHook::operator=(IatHook&& other) noexcept {
    if (this != &other) {
        Restore();
        original_ = std::exchange(other.original_, nullptr);
        replacement_ = std::exchange(other.replacement_, nullptr);
        thunk_ = std::exchange(other.thunk_, nullptr);
    }
    return *this;
}

bool IatHook::Install(std::string_view module, std::string_view function, const void* replacement) {
    Restore();

    ModuleView view{};
    const auto imports = EnumerateImports(module, view);
    if (!imports) {
        return false;
    }

    for (const auto& entry : *imports) {
        if (!entry.import_by_name || entry.name != function) {
            continue;
        }

        original_ = entry.original;
        replacement_ = replacement;
        thunk_ = entry.thunk_slot;
        MakeWritable(thunk_);
        *thunk_ = const_cast<void*>(replacement);
        return true;
    }

    return false;
}

bool IatHook::Installed() const noexcept {
    return thunk_ != nullptr;
}

void IatHook::Restore() noexcept {
    if (thunk_ && *thunk_ == replacement_) {
        MakeWritable(thunk_);
        *thunk_ = original_;
    }
    original_ = nullptr;
    replacement_ = nullptr;
    thunk_ = nullptr;
}

const void* IatHook::Original() const noexcept {
    return original_;
}

void** IatHook::Thunk() const noexcept {
    return thunk_;
}

} // namespace spf