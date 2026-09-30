#include <windows.h>

#include <cwchar>

int wmain(int argc, wchar_t** argv) {
    if (argc != 4) return 2;
    HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]);
    HANDLE stop = OpenEventW(SYNCHRONIZE, FALSE, argv[3]);
    if (!ready || !stop) {
        if (ready) CloseHandle(ready);
        if (stop) CloseHandle(stop);
        return 3;
    }
    HMODULE module = LoadLibraryW(argv[1]);
    if (!module) {
        CloseHandle(ready);
        CloseHandle(stop);
        return 4;
    }
    SetEvent(ready);
    CloseHandle(ready);
    const DWORD wait = WaitForSingleObject(stop, 15000);
    CloseHandle(stop);
    return wait == WAIT_OBJECT_0 ? 0 : 5;
}
