#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace spf {

extern "C" __declspec(noinline) void* SpoofDispatch(
    void* a0, void* a1, void* a2, void* a3,
    void* ctx, void* pad,
    void* a4, void* a5, void* a6, void* a7, void* a8, void* a9);

struct SpoofContext {
    void* trampoline;
    void* target;
    void* original_ret;
    void* saved_rbx;
};

__declspec(noinline) void* DispatchN(const std::array<std::uintptr_t, 10>& packed, std::size_t count, SpoofContext* ctx);

class Spoofer {
public:
    explicit Spoofer(std::wstring_view spoof_module = L"wininet.dll", std::vector<std::uint8_t> banned = {0x00});

    [[nodiscard]] bool Ready() const noexcept;
    [[nodiscard]] const void* Gadget() const noexcept;
    [[nodiscard]] std::wstring_view SpoofModule() const noexcept;

    template <typename Ret, typename... Args>
    Ret Call(Ret (*fn)(Args...), Args... args);

private:
    void* ResolveGadget(std::wstring_view module_name);

    std::wstring module_name_;
    std::vector<std::uint8_t> banned_;
    void* gadget_ = nullptr;
};

template <typename T>
[[nodiscard]] constexpr bool AbiSafeArg() noexcept {
    return std::is_integral_v<T> || std::is_pointer_v<T> || std::is_enum_v<T>;
}

template <typename T>
[[nodiscard]] constexpr std::uintptr_t PackArg(T value) noexcept {
    if constexpr (std::is_pointer_v<T>) {
        return reinterpret_cast<std::uintptr_t>(value);
    } else {
        return static_cast<std::uintptr_t>(static_cast<std::make_unsigned_t<T>>(value));
    }
}

template <typename Ret, typename... Args>
Ret Spoofer::Call(Ret (*fn)(Args...), Args... args) {
    static_assert(sizeof...(Args) <= 10, "max 10 arguments");
    static_assert((AbiSafeArg<Args>() && ...), "integral or pointer arguments only");
    static_assert(!std::is_floating_point_v<Ret> && ((!std::is_floating_point_v<Args>) && ...),
                  "floating point ABI is not supported");

    std::array<std::uintptr_t, 10> packed{};
    std::size_t index = 0;
    ((packed[index++] = PackArg(args)), ...);

    SpoofContext ctx{};
    ctx.trampoline = gadget_;
    ctx.target = reinterpret_cast<void*>(fn);

    void* raw = nullptr;
    switch (sizeof...(Args)) {
        case 0:  raw = DispatchN(packed, 0, &ctx);  break;
        case 1:  raw = DispatchN(packed, 1, &ctx);  break;
        case 2:  raw = DispatchN(packed, 2, &ctx);  break;
        case 3:  raw = DispatchN(packed, 3, &ctx);  break;
        case 4:  raw = DispatchN(packed, 4, &ctx);  break;
        case 5:  raw = DispatchN(packed, 5, &ctx);  break;
        case 6:  raw = DispatchN(packed, 6, &ctx);  break;
        case 7:  raw = DispatchN(packed, 7, &ctx);  break;
        case 8:  raw = DispatchN(packed, 8, &ctx);  break;
        case 9:  raw = DispatchN(packed, 9, &ctx);  break;
        default: raw = DispatchN(packed, 10, &ctx); break;
    }

    if constexpr (std::is_void_v<Ret>) {
        return;
    } else if constexpr (std::is_pointer_v<Ret>) {
        return static_cast<Ret>(raw);
    } else {
        return static_cast<Ret>(reinterpret_cast<std::uintptr_t>(raw));
    }
}

namespace detail {
__declspec(noinline) void* Call0(SpoofContext* ctx);
__declspec(noinline) void* Call1(SpoofContext* ctx, void* a0);
__declspec(noinline) void* Call2(SpoofContext* ctx, void* a0, void* a1);
__declspec(noinline) void* Call3(SpoofContext* ctx, void* a0, void* a1, void* a2);
__declspec(noinline) void* Call4(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3);
__declspec(noinline) void* Call5(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4);
__declspec(noinline) void* Call6(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5);
__declspec(noinline) void* Call7(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
__declspec(noinline) void* Call8(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7);
__declspec(noinline) void* Call9(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7, void* a8);
__declspec(noinline) void* Call10(SpoofContext* ctx, void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7, void* a8, void* a9);
} // namespace detail

} // namespace spf