#pragma once
#include <windows.h>
#include <atomic>
#include <string>

namespace privateclip {
void Initialize(std::atomic<LONG>* calls) noexcept;
bool Attach(bool install) noexcept; // Part of the owner's Detours transaction.
void Arm(const std::wstring& mappingName) noexcept;
void Poll() noexcept;
bool CanDetach() noexcept;
bool Blocking() noexcept;
DWORD Diagnostics() noexcept;
void Fault() noexcept;
bool Open(HWND owner, BOOL& result) noexcept;
bool Close(BOOL& result) noexcept;
bool Empty(BOOL& result) noexcept;
bool Get(UINT format, HANDLE& result) noexcept;
bool Set(UINT format, HANDLE memory, HANDLE& result) noexcept;
} // namespace privateclip
