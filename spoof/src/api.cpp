#include "spoof/api.hpp"

#include "spoof/gadget.hpp"
#include "spoof/log.hpp"

#include <Windows.h>

namespace spf {
namespace {

constexpr std::uint8_t kJmpRbxGadget[] = {0xFF, 0x23};

} // namespace

__declspec(noinline) void* DispatchN(const std::array<std::uintptr_t, 10>& packed, std::size_t count, SpoofContext* ctx) {
    switch (count) {
        case 0:  return detail::Call0(ctx);
        case 1:  return detail::Call1(ctx, (void*)packed[0]);
        case 2:  return detail::Call2(ctx, (void*)packed[0], (void*)packed[1]);
        case 3:  return detail::Call3(ctx, (void*)packed[0], (void*)packed[1], (void*)packed[2]);
        case 4:  return detail::Call4(ctx, (void*)packed[0], (void*)packed[1], (void*)packed[2], (void*)packed[3]);
        case 5:  return detail::Call5(ctx, (void*)packed[0], (void*)packed[1], (void*)packed[2], (void*)packed[3], (void*)packed[4]);
        case 6:  return detail::Call6(ctx, (void*)packed[0], (void*)packed[1], (void*)packed[2], (void*)packed[3], (void*)packed[4], (void*)packed[5]);
        case 7:  return detail::Call7(ctx, (void*)packed[0], (void*)packed[1], (void*)packed[2], (void*)packed[3], (void*)packed[4], (void*)packed[5], (void*)packed[6]);
        case 8:  return detail::Call8(ctx, (void*)packed[0], (void*)packed[1], (void*)packed[2], (void*)packed[3], (void*)packed[4], (void*)packed[5], (void*)packed[6], (void*)packed[7]);
        case 9:  return detail::Call9(ctx, (void*)packed[0], (void*)packed[1], (void*)packed[2], (void*)packed[3], (void*)packed[4], (void*)packed[5], (void*)packed[6], (void*)packed[7], (void*)packed[8]);
        default: return detail::Call10(ctx, (void*)packed[0], (void*)packed[1], (void*)packed[2], (void*)packed[3], (void*)packed[4], (void*)packed[5], (void*)packed[6], (void*)packed[7], (void*)packed[8], (void*)packed[9]);
    }
}

namespace detail {

void* Call0(SpoofContext* ctx) {
    return SpoofDispatch(nullptr, nullptr, nullptr, nullptr, ctx, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

void* Call1(SpoofContext* ctx, void* a0) {
    return SpoofDispatch(a0, nullptr, nullptr, nullptr, ctx, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

void* Call2(SpoofContext* ctx, void* a0, void* a1) {
    return SpoofDispatch(a0, a1, nullptr, nullptr, ctx, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

void* Call3(SpoofContext* ctx, void* a0, void* a1, void* a2) {
    return SpoofDispatch(a0, a1, a2, nullptr, ctx, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

void* Call4(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3) {
    return SpoofDispatch(a0, a1, a2, a3, ctx, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

void* Call5(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4) {
    return SpoofDispatch(a0, a1, a2, a3, ctx, nullptr, a4, nullptr, nullptr, nullptr, nullptr, nullptr);
}

void* Call6(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5) {
    return SpoofDispatch(a0, a1, a2, a3, ctx, nullptr, a4, a5, nullptr, nullptr, nullptr, nullptr);
}

void* Call7(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    return SpoofDispatch(a0, a1, a2, a3, ctx, nullptr, a4, a5, a6, nullptr, nullptr, nullptr);
}

void* Call8(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7) {
    return SpoofDispatch(a0, a1, a2, a3, ctx, nullptr, a4, a5, a6, a7, nullptr, nullptr);
}

void* Call9(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7, void* a8) {
    return SpoofDispatch(a0, a1, a2, a3, ctx, nullptr, a4, a5, a6, a7, a8, nullptr);
}

void* Call10(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7, void* a8, void* a9) {
    return SpoofDispatch(a0, a1, a2, a3, ctx, nullptr, a4, a5, a6, a7, a8, a9);
}

} // namespace detail

void* Spoofer::ResolveGadget(std::wstring_view module_name) {
    const std::wstring wide_name(module_name);
    HMODULE module = GetModuleHandleW(wide_name.c_str());
    if (!module) {
        module = LoadLibraryW(wide_name.c_str());
    }
    if (!module) {
        LOG_WARN("module '%ls' is not present, skipping", wide_name.c_str());
        return nullptr;
    }

    const auto view = ModuleView::Open(module);
    if (!view) {
        LOG_WARN("failed to parse module '%ls'", wide_name.c_str());
        return nullptr;
    }

    Scanner scanner(banned_);
    const auto found = scanner.FindFirst(*view, std::span<const std::uint8_t>(kJmpRbxGadget));
    if (!found) {
        LOG_WARN("no JMP [RBX] gadget (FF 23) found in '%ls'", wide_name.c_str());
        return nullptr;
    }

    gadget_ = const_cast<void*>(found->address);
    LOG_DEBUG("gadget resolved: %ls+0x%llX (section '%s', offset 0x%llX)",
              wide_name.c_str(),
              static_cast<unsigned long long>(found->rva),
              std::string(found->section_name).c_str(),
              static_cast<unsigned long long>(found->section_offset));

    return gadget_;
}

Spoofer::Spoofer(std::wstring_view spoof_module, std::vector<std::uint8_t> banned)
    : module_name_(spoof_module),
      banned_(std::move(banned)) {
    gadget_ = ResolveGadget(module_name_);

    if (!gadget_) {
        for (const auto* fallback : {L"kernel32.dll", L"ntdll.dll"}) {
            gadget_ = ResolveGadget(fallback);
            if (gadget_) {
                module_name_ = fallback;
                break;
            }
        }
    }
}

bool Spoofer::Ready() const noexcept {
    return gadget_ != nullptr;
}

const void* Spoofer::Gadget() const noexcept {
    return gadget_;
}

std::wstring_view Spoofer::SpoofModule() const noexcept {
    return module_name_;
}

} // namespace spf