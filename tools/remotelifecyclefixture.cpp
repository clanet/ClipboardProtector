#include <windows.h>

#ifdef _M_IX86
#pragma comment(linker, "/EXPORT:ClipHookStartRemote=_ClipHookStartRemote@4")
#endif

// A private fixture with no hooks, clipboard access or background work. The
// smoke target loads two references so an extra release is observable.
extern "C" __declspec(dllexport) DWORD WINAPI ClipHookStartRemote(void*) {
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
