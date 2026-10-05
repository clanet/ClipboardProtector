#include <windows.h>
#include "detours.h"
#include <stdio.h>

namespace {
__declspec(noinline) LONG WINAPI Target(LONG value) { return (value * 17 + 9) ^ 0x13579; }
auto realTarget = Target;
LONG WINAPI Hook(LONG value) { return realTarget(value) + 1; }

struct HeapOwner {
    HANDLE ready;
    HANDLE release;
};

DWORD WINAPI HoldHeap(void* argument) {
    auto& owner = *static_cast<HeapOwner*>(argument);
    if (!HeapLock(GetProcessHeap())) return 1;
    SetEvent(owner.ready);
    WaitForSingleObject(owner.release, INFINITE);
    HeapUnlock(GetProcessHeap());
    return 0;
}

bool Transition(bool install) {
    if (DetourTransactionBegin() != NO_ERROR) return false;
    const LONG staged = install
        ? DetourAttach(reinterpret_cast<PVOID*>(&realTarget), Hook)
        : DetourDetach(reinterpret_cast<PVOID*>(&realTarget), Hook);
    if (staged != NO_ERROR) { DetourTransactionAbort(); return false; }
    HeapOwner owner{CreateEventW(nullptr, TRUE, FALSE, nullptr),
                    CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    HANDLE thread = owner.ready && owner.release
        ? CreateThread(nullptr, 0, HoldHeap, &owner, 0, nullptr) : nullptr;
    HANDLE waits[] = {owner.ready, thread};
    bool ok = thread && WaitForMultipleObjects(2, waits, FALSE, 3000) == WAIT_OBJECT_0;
    // This deliberately suspends only our test thread while it owns the CRT
    // heap. Any transaction-node new/delete on that heap deadlocks here.
    if (ok) ok = DetourUpdateThread(thread) == NO_ERROR;
    const LONG result = ok ? DetourTransactionCommit() : DetourTransactionAbort();
    SetEvent(owner.release);
    if (thread) {
        ok = WaitForSingleObject(thread, 3000) == WAIT_OBJECT_0 && ok;
        CloseHandle(thread);
    }
    if (owner.ready) CloseHandle(owner.ready);
    if (owner.release) CloseHandle(owner.release);
    return ok && result == NO_ERROR;
}
}

int main() {
    // Volatile prevents the compiler folding calls around the live patch.
    LONG (WINAPI* volatile invoke)(LONG) = Target;
    const LONG baseline = invoke(3);
    if (!Transition(true)) return 1;
    if (invoke(3) != baseline + 1) return 2;
    if (!Transition(false)) return 3;
    if (invoke(3) != baseline) return 4;
    puts("attach=1 detach=1 suspended-heap-owner=1");
    return 0;
}
