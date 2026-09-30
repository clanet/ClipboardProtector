#include "privateclip.h"
#include "../common/privateclip.h"
#include "detours.h"
#include <ole2.h>
#include <shlobj.h>
#include <algorithm>
#include <vector>
#include <cstring>

namespace privateclip {
namespace {
SRWLOCK mutex = SRWLOCK_INIT;
struct Lock { Lock(){AcquireSRWLockExclusive(&mutex);} ~Lock(){ReleaseSRWLockExclusive(&mutex);} };
std::atomic<bool> gate{false};
#ifdef CLIP_TEST_EXPORTS
std::atomic<DWORD> diagnostics{0};
#endif
void Record(DWORD flags) noexcept {
#ifdef CLIP_TEST_EXPORTS
    diagnostics.fetch_or(flags);
#else
    (void)flags;
#endif
}
std::atomic<LONG> liveObjects{0};
std::atomic<LONG>* activeCalls = nullptr;
struct Call { Call(){if(activeCalls)++*activeCalls;} ~Call(){if(activeCalls)--*activeCalls;} };
HANDLE mapping = nullptr;
clip::PrivateClipSession* session = nullptr;
bool quarantined = false, opened = false, closed = false, used = false, unicode = false;
DWORD failure = clip::kPrivateOk;
DWORD rootThread = 0, clipboardThread = 0;
unsigned scopes = 0;
bool inputObserved = false;
HHOOK messageHook = nullptr, beforeHook = nullptr, afterHook = nullptr;
HHOOK rootMessageHook = nullptr, rootBeforeHook = nullptr, rootAfterHook = nullptr;
std::atomic<DWORD> hookGeneration{0};
thread_local unsigned windowDepth = 0;
thread_local DWORD windowGeneration = 0;
thread_local bool windowScopes[128] = {};
HWND derivedWindow = nullptr;
DWORD derivedScan = 0, derivedTag = 0;
thread_local unsigned inputDepth = 0;
std::vector<HGLOBAL> owned;
HGLOBAL pasteHandles[4] = {};
constexpr UINT textFormats[] = {CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT, CF_LOCALE};

static decltype(&DispatchMessageW) RealDispatchW = DispatchMessageW;
static decltype(&TranslateMessage) RealTranslateMessage = TranslateMessage;
static decltype(&DispatchMessageA) RealDispatchA = DispatchMessageA;
static decltype(&TranslateAcceleratorW) RealTranslateW = TranslateAcceleratorW;
static decltype(&TranslateAcceleratorA) RealTranslateA = TranslateAcceleratorA;
static decltype(&IsDialogMessageW) RealDialogW = IsDialogMessageW;
static decltype(&IsDialogMessageA) RealDialogA = IsDialogMessageA;
static decltype(&IsClipboardFormatAvailable) RealAvailable = IsClipboardFormatAvailable;
static decltype(&EnumClipboardFormats) RealEnum = EnumClipboardFormats;
static decltype(&CountClipboardFormats) RealCount = CountClipboardFormats;
static decltype(&GetPriorityClipboardFormat) RealPriority = GetPriorityClipboardFormat;
static decltype(&GetClipboardOwner) RealOwner = GetClipboardOwner;
static decltype(&GetOpenClipboardWindow) RealOpenWindow = GetOpenClipboardWindow;
static decltype(&OleSetClipboard) RealOleSet = OleSetClipboard;
static decltype(&OleGetClipboard) RealOleGet = OleGetClipboard;
static decltype(&OleFlushClipboard) RealOleFlush = OleFlushClipboard;
static decltype(&OleIsCurrentClipboard) RealOleCurrent = OleIsCurrentClipboard;
using NativeBool = BOOL (WINAPI*)();
static NativeBool RealNativeClose = nullptr, RealNativeEmpty = nullptr;
static decltype(&IsClipboardFormatAvailable) RealNativeAvailable = nullptr;
static decltype(&EnumClipboardFormats) RealNativeEnum = nullptr;
static decltype(&CountClipboardFormats) RealNativeCount = nullptr;
static decltype(&GetPriorityClipboardFormat) RealNativePriority = nullptr;

void Wipe(HGLOBAL memory) noexcept {
    if (!memory) return;
    const SIZE_T bytes = GlobalSize(memory);
    void* data = GlobalLock(memory);
    if (data) { SecureZeroMemory(data, bytes); GlobalUnlock(memory); }
    GlobalFree(memory);
}
void ClearHandles() noexcept {
    for (HGLOBAL h : owned) Wipe(h);
    owned.clear(); std::fill(std::begin(pasteHandles), std::end(pasteHandles), nullptr);
}
void ReleaseSession() noexcept {
    for (HHOOK* hook : {&messageHook, &beforeHook, &afterHook, &rootMessageHook, &rootBeforeHook, &rootAfterHook}) {
        if (*hook) UnhookWindowsHookEx(*hook);
        *hook = nullptr;
    }
    ClearHandles();
    if (session) UnmapViewOfFile(session);
    if (mapping) CloseHandle(mapping);
    session = nullptr; mapping = nullptr;
    opened = closed = used = unicode = false;
    failure = clip::kPrivateOk;
    inputObserved = false;
    rootThread = clipboardThread = 0;
    derivedWindow = nullptr; derivedScan = derivedTag = 0;
    gate.store(quarantined, std::memory_order_release);
}
bool Target() noexcept {
    if (!session) return false;
    const HWND foreground = reinterpret_cast<HWND>(static_cast<ULONG_PTR>(session->foreground));
    GUITHREADINFO info = {sizeof(info)};
    return GetForegroundWindow() == foreground &&
        GetGUIThreadInfo(session->threadId, &info) &&
        info.hwndFocus == reinterpret_cast<HWND>(static_cast<ULONG_PTR>(session->focus));
}
bool Inside() noexcept {
    return session && inputObserved &&
        (GetCurrentThreadId() == session->threadId || GetCurrentThreadId() == rootThread) && Target() &&
        clip::PrivateState(session) == clip::kPrivateRunning &&
        GetTickCount64() <= session->deadline;
}
void Deny() noexcept { SetLastError(ERROR_ACCESS_DENIED); }
void Fail(DWORD reason) noexcept {
    failure = reason;
    if (session) session->error = reason;
}
void Quarantine(DWORD reason) noexcept {
    quarantined = true;
    if (session) {
        session->error = reason;
        session->reserved = 1;
        SecureZeroMemory(session->text, sizeof(session->text));
        session->length = 0;
        InterlockedExchange(&session->state, clip::kPrivateFailed);
    }
    if (!scopes) ReleaseSession();
}

bool Begin(const MSG* msg) noexcept {
    if (!msg || !gate.load(std::memory_order_acquire)) return false;
    Lock lock;
    if (!session || inputDepth || GetCurrentThreadId() != session->threadId) return false;
    const bool tagged = static_cast<DWORD>(GetMessageExtraInfo()) == session->inputTag;
    const bool key = msg->message == WM_KEYDOWN &&
        msg->wParam == static_cast<WPARAM>(session->operation ? 'V' : 'C') && tagged && (GetKeyState(VK_CONTROL) & 0x8000);
    const bool character = msg->message == WM_CHAR &&
        msg->wParam == static_cast<WPARAM>(session->operation ? 0x16 : 0x03) &&
        (tagged || (derivedTag == session->inputTag && msg->hwnd == derivedWindow &&
                    (static_cast<DWORD>(msg->lParam) & 0x00ff0000) == derivedScan));
    if (!key && !character) return false;
    const LONG state = clip::PrivateState(session);
    if ((state != clip::kPrivateSending && state != clip::kPrivateRunning) ||
        !Target() || GetTickCount64() > session->deadline) return false;
    InterlockedExchange(&session->state, clip::kPrivateRunning);
    inputObserved = true;
    Record(character ? 2 : 1);
    if (character) derivedWindow = nullptr;
    ++inputDepth; ++scopes;
    return true;
}
void Finish(bool consumed) noexcept {
    if (!session || scopes) return;
    // Standard Edit controls perform Ctrl+C/V on the translated WM_CHAR. Keep
    // the gate armed across a key-down/accelerator that has not touched it yet.
    if (!used && failure == clip::kPrivateOk &&
        clip::PrivateState(session) == clip::kPrivateRunning) return;
    const bool completed = consumed && closed && !opened && used &&
        failure == clip::kPrivateOk && clip::PrivateState(session) == clip::kPrivateRunning &&
        GetTickCount64() <= session->deadline &&
        (session->operation || session->length);
    if (!completed) {
        Quarantine(failure != clip::kPrivateOk ? failure : clip::kPrivateNoText);
        return;
    }
    session->error = clip::kPrivateOk;
    session->reserved = quarantined ? 1 : 0;
    InterlockedExchange(&session->state, clip::kPrivateDone);
    ReleaseSession();
}
void End(bool consumed) noexcept {
    Lock lock;
    --inputDepth; --scopes;
    Finish(consumed);
}
struct ClipboardCallScope {
    bool entered = false;
    explicit ClipboardCallScope(DWORD operation) {
        Lock lock;
        if (Inside() && session->operation == operation) {
            ++inputDepth; ++scopes; entered = true;
        }
    }
    ~ClipboardCallScope() { if (entered) End(true); }
};
struct InputScope {
    bool entered;
    bool consumed = true;
    explicit InputScope(const MSG* msg):entered(Begin(msg)){}
    ~InputScope(){if(entered)End(consumed);}
};
LRESULT CALLBACK ObserveInput(int code, WPARAM removed, LPARAM parameter) {
    Call call;
    if (code >= 0 && removed == PM_REMOVE && parameter) {
        const MSG& message = *reinterpret_cast<MSG*>(parameter);
        Lock lock;
        if (session && message.message == WM_KEYDOWN &&
            message.wParam == static_cast<WPARAM>(session->operation ? 'V' : 'C') &&
            static_cast<DWORD>(GetMessageExtraInfo()) == session->inputTag && Target() &&
            clip::PrivateState(session) == clip::kPrivateSending) {
            inputObserved = true;
            InterlockedExchange(&session->state, clip::kPrivateRunning);
            Record(512);
        }
    }
    return CallNextHookEx(nullptr, code, removed, parameter);
}
LRESULT CALLBACK BeforeWindow(int code, WPARAM sent, LPARAM parameter) {
    Call call;
    if (code >= 0) {
        const DWORD generation = hookGeneration.load();
        if (windowGeneration != generation) { windowDepth = 0; windowGeneration = generation; }
        const unsigned frame = windowDepth++;
        if (frame < _countof(windowScopes)) {
            windowScopes[frame] = false;
            Lock lock;
            const auto* message = reinterpret_cast<CWPSTRUCT*>(parameter);
            const HWND foreground = session ? reinterpret_cast<HWND>(static_cast<ULONG_PTR>(session->foreground)) : nullptr;
            const HWND focus = session ? reinterpret_cast<HWND>(static_cast<ULONG_PTR>(session->focus)) : nullptr;
            const bool related = message && foreground &&
                (message->hwnd == foreground || message->hwnd == focus || IsChild(foreground, message->hwnd));
            const bool command = message && (message->message == WM_KEYDOWN ||
                message->message == WM_CHAR || message->message == WM_COPY ||
                message->message == WM_PASTE || message->message == WM_COMMAND ||
                message->message == WM_NOTIFY || message->message >= WM_USER);
            if (session && inputObserved && related && command && Target() &&
                clip::PrivateState(session) == clip::kPrivateRunning &&
                (GetCurrentThreadId() == session->threadId || GetCurrentThreadId() == rootThread)) {
                ++inputDepth; ++scopes;
                windowScopes[frame] = true;
                Record(1024);
            }
        }
    }
    return CallNextHookEx(nullptr, code, sent, parameter);
}
LRESULT CALLBACK AfterWindow(int code, WPARAM sent, LPARAM parameter) {
    Call call;
    if (code >= 0 && windowDepth) {
        const unsigned frame = --windowDepth;
        if (frame < _countof(windowScopes) && windowScopes[frame]) {
            windowScopes[frame] = false;
            End(true);
        }
    }
    return CallNextHookEx(nullptr, code, sent, parameter);
}
LRESULT WINAPI DispatchW(const MSG* msg) { Call call; InputScope scope(msg); return RealDispatchW(msg); }
LRESULT WINAPI DispatchA(const MSG* msg) { Call call; InputScope scope(msg); return RealDispatchA(msg); }
BOOL WINAPI Translate(const MSG* msg) {
    Call call;
    if (msg && Blocking()) {
        Lock lock;
        if (session && GetCurrentThreadId() == session->threadId &&
            static_cast<DWORD>(GetMessageExtraInfo()) == session->inputTag &&
            msg->message == WM_KEYDOWN && msg->wParam == static_cast<WPARAM>(session->operation ? 'V' : 'C')) {
            // TranslateMessage does not preserve dwExtraInfo on WM_CHAR. Bind
            // one derived control character to the originating HWND/scan code.
            derivedWindow = msg->hwnd; derivedScan = msg->lParam & 0x00ff0000; derivedTag = session->inputTag;
        }
    }
    return RealTranslateMessage(msg);
}
int WINAPI TranslateW(HWND h,HACCEL a,LPMSG msg) {
    Call call; InputScope scope(msg); int result=RealTranslateW(h,a,msg); scope.consumed=result!=0; return result;
}
int WINAPI TranslateA(HWND h,HACCEL a,LPMSG msg) {
    Call call; InputScope scope(msg); int result=RealTranslateA(h,a,msg); scope.consumed=result!=0; return result;
}
BOOL WINAPI DialogW(HWND h,LPMSG msg) {
    Call call; InputScope scope(msg); BOOL result=RealDialogW(h,msg); scope.consumed=result!=FALSE; return result;
}
BOOL WINAPI DialogA(HWND h,LPMSG msg) {
    Call call; InputScope scope(msg); BOOL result=RealDialogA(h,msg); scope.consumed=result!=FALSE; return result;
}

bool Capture(UINT format,HGLOBAL memory) {
    const SIZE_T bytes = GlobalSize(memory);
    if (!bytes || bytes > (clip::kPrivateClipMaxChars + 1) * 4u) {
        Fail(clip::kPrivateTooLarge); return false;
    }
    const void* data = GlobalLock(memory);
    if (!data) { Fail(clip::kPrivateInvalidData); return false; }
    struct Unlock { HGLOBAL h; ~Unlock(){GlobalUnlock(h);} } unlock{memory};
    DWORD length = 0;
    if (format == CF_UNICODETEXT) {
        const auto* text = static_cast<const wchar_t*>(data);
        const size_t capacity = bytes / sizeof(wchar_t);
        while (length < capacity && text[length]) ++length;
        if (length == capacity || length > clip::kPrivateClipMaxChars) {
            Fail(clip::kPrivateTooLarge); return false;
        }
        std::copy_n(text, length, session->text);
        unicode = true;
    } else {
        const auto* text = static_cast<const char*>(data);
        while (length < bytes && text[length]) ++length;
        if (length == bytes) { Fail(clip::kPrivateInvalidData); return false; }
        if (unicode) return true;
        const int converted = MultiByteToWideChar(format == CF_OEMTEXT ? CP_OEMCP : CP_ACP,
            0, text, length, session->text, clip::kPrivateClipMaxChars);
        if (!converted && length) { Fail(clip::kPrivateInvalidData); return false; }
        length = converted;
    }
    for (DWORD i=0;i<length;++i) {
        wchar_t c=session->text[i];
        if(c<L' ' && c!=L'\r' && c!=L'\n' && c!=L'\t') {
            Fail(clip::kPrivateInvalidData); return false;
        }
    }
    session->text[length]=0; session->length=length;
    return true;
}
HGLOBAL TextHandle(UINT format) {
    const auto found=std::find(std::begin(textFormats),std::end(textFormats),format);
    if(found==std::end(textFormats))return nullptr;
    const size_t index=found-std::begin(textFormats);
    if (pasteHandles[index]) return pasteHandles[index];
    SIZE_T bytes=(session->length+1)*sizeof(wchar_t);
    if(format==CF_LOCALE)bytes=sizeof(LCID);
    if(format==CF_TEXT || format==CF_OEMTEXT) {
        bytes=WideCharToMultiByte(format==CF_TEXT?CP_ACP:CP_OEMCP,0,session->text,
            static_cast<int>(session->length+1),nullptr,0,nullptr,nullptr);
        if(!bytes)return nullptr;
    }
    HGLOBAL h=GlobalAlloc(GMEM_MOVEABLE|GMEM_ZEROINIT,bytes);
    if(!h) return nullptr;
    void* data=GlobalLock(h);
    if(!data){GlobalFree(h);return nullptr;}
    if(format==CF_UNICODETEXT)memcpy(data,session->text,bytes);
    else if(format==CF_LOCALE)*static_cast<LCID*>(data)=GetUserDefaultLCID();
    else WideCharToMultiByte(format==CF_TEXT?CP_ACP:CP_OEMCP,0,session->text,
        static_cast<int>(session->length+1),static_cast<char*>(data),static_cast<int>(bytes),nullptr,nullptr);
    GlobalUnlock(h);
    try {owned.push_back(h);} catch (...) {Wipe(h);throw;}
    pasteHandles[index]=h;return h;
}
BOOL WINAPI Available(UINT format) {
    Call call;
    if(!Blocking()) return RealAvailable(format);
    Lock lock;
    Record(256);
    return Inside() && session->operation==1 &&
        std::find(std::begin(textFormats),std::end(textFormats),format)!=std::end(textFormats);
}
UINT WINAPI Enum(UINT format) {
    Call call;
    if(!Blocking())return RealEnum(format);
    Lock lock;
    if(!Inside() || !opened){Deny();return 0;}
    SetLastError(ERROR_SUCCESS);
    if(session->operation!=1)return 0;
    if(!format)return textFormats[0];
    const auto found=std::find(std::begin(textFormats),std::end(textFormats),format);
    return found!=std::end(textFormats) && found+1!=std::end(textFormats) ? found[1] : 0;
}
int WINAPI Count() {
    Call call;if(!Blocking())return RealCount();Lock lock;
    return Inside() && session->operation==1 ? static_cast<int>(_countof(textFormats)) : 0;
}
int WINAPI Priority(UINT* formats,int count) {
    Call call;if(!Blocking())return RealPriority(formats,count);
    Lock lock;
    if(!Inside() || session->operation!=1)return 0;
    if(!formats || count<0 || count>1024){Deny();return -1;}
    for(int i=0;i<count;++i)
        if(std::find(std::begin(textFormats),std::end(textFormats),formats[i])!=std::end(textFormats))return formats[i];
    return -1;
}
HWND WINAPI Owner(){Call call;if(!Blocking())return RealOwner();return nullptr;}
HWND WINAPI OpenWindow(){Call call;if(!Blocking())return RealOpenWindow();return nullptr;}
BOOL WINAPI NativeClose(){Call call;BOOL result=FALSE;return Close(result)?result:RealNativeClose();}
BOOL WINAPI NativeEmpty(){Call call;BOOL result=FALSE;return Empty(result)?result:RealNativeEmpty();}
BOOL WINAPI NativeAvailable(UINT f){Call call;return Blocking()?Available(f):RealNativeAvailable(f);}
UINT WINAPI NativeEnum(UINT f){Call call;return Blocking()?Enum(f):RealNativeEnum(f);}
int WINAPI NativeCount(){Call call;return Blocking()?Count():RealNativeCount();}
int WINAPI NativePriority(UINT* f,int n){Call call;return Blocking()?Priority(f,n):RealNativePriority(f,n);}

// Minimal immutable text IDataObject. Every GetData returns a fresh caller-owned
// allocation, as OLE requires; neither OleGetClipboard nor OleSetClipboard is used.
class TextObject final : public IDataObject {
    std::atomic<ULONG> refs{1};
    std::vector<wchar_t> text;
public:
    TextObject(const wchar_t* data,size_t length):text(data,data+length+1){++liveObjects;}
    ~TextObject(){SecureZeroMemory(text.data(),text.size()*sizeof(wchar_t));--liveObjects;}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if(!out)return E_POINTER;*out=nullptr;
        if(iid!=IID_IUnknown && iid!=IID_IDataObject)return E_NOINTERFACE;
        *out=static_cast<IDataObject*>(this);AddRef();return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override{return ++refs;}
    ULONG STDMETHODCALLTYPE Release() override{Call call;ULONG n=--refs;if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE QueryGetData(FORMATETC* f) override {
        if(!f)return E_POINTER;
        return f->cfFormat==CF_UNICODETEXT && (f->tymed&TYMED_HGLOBAL) &&
            f->dwAspect==DVASPECT_CONTENT && f->lindex==-1 ? S_OK : DV_E_FORMATETC;
    }
    HRESULT STDMETHODCALLTYPE GetData(FORMATETC* f,STGMEDIUM* out) override {
        if(!out)return E_POINTER;*out={};HRESULT hr=QueryGetData(f);if(FAILED(hr))return hr;
        HGLOBAL h=GlobalAlloc(GMEM_MOVEABLE,text.size()*sizeof(wchar_t));if(!h)return E_OUTOFMEMORY;
        void* p=GlobalLock(h);if(!p){GlobalFree(h);return E_OUTOFMEMORY;}
        memcpy(p,text.data(),text.size()*sizeof(wchar_t));GlobalUnlock(h);
        out->tymed=TYMED_HGLOBAL;out->hGlobal=h;return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDataHere(FORMATETC*,STGMEDIUM*) override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE GetCanonicalFormatEtc(FORMATETC*,FORMATETC* out) override {
        if(!out)return E_POINTER;out->ptd=nullptr;return DATA_S_SAMEFORMATETC;
    }
    HRESULT STDMETHODCALLTYPE SetData(FORMATETC*,STGMEDIUM*,BOOL) override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE EnumFormatEtc(DWORD direction,IEnumFORMATETC** out) override {
        if(!out)return E_POINTER;*out=nullptr;if(direction!=DATADIR_GET)return E_NOTIMPL;
        FORMATETC f={CF_UNICODETEXT,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};
        return SHCreateStdEnumFmtEtc(1,&f,out);
    }
    HRESULT STDMETHODCALLTYPE DAdvise(FORMATETC*,DWORD,IAdviseSink*,DWORD*) override{return OLE_E_ADVISENOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE DUnadvise(DWORD) override{return OLE_E_ADVISENOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE EnumDAdvise(IEnumSTATDATA**) override{return OLE_E_ADVISENOTSUPPORTED;}
};
HRESULT WINAPI OleSet(IDataObject* object) {
    Call call;if(!Blocking())return RealOleSet(object);
    ClipboardCallScope scope(0);
    if(!scope.entered){Deny();return E_ACCESSDENIED;}
    // Providers may render on demand; call outside our lock to allow reentrancy.
    FORMATETC f={CF_UNICODETEXT,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};
    STGMEDIUM medium={};
    HRESULT hr=object ? object->GetData(&f,&medium) : E_INVALIDARG;
    bool copied=false;
    if(SUCCEEDED(hr) && medium.tymed==TYMED_HGLOBAL && medium.hGlobal) {
        try {Lock lock;if(Inside()){copied=Capture(CF_UNICODETEXT,medium.hGlobal);used=closed=true;}}
        catch (...) {Fault();}
    }
    if(SUCCEEDED(hr))ReleaseStgMedium(&medium);
    if(!copied){Lock lock;Fail(clip::kPrivateUnsupported);return DV_E_FORMATETC;}
    return S_OK;
}
HRESULT WINAPI OleGet(IDataObject** object) {
    Call call;if(!Blocking())return RealOleGet(object);
    if(!object)return E_POINTER;*object=nullptr;
    ClipboardCallScope scope(1);
    if(!scope.entered)return E_ACCESSDENIED;
    try {
        Lock lock;if(!Inside() || session->operation!=1)return E_ACCESSDENIED;
        *object=new TextObject(session->text,session->length);used=closed=true;return S_OK;
    } catch (...) {Fault();return E_OUTOFMEMORY;}
}
HRESULT WINAPI OleFlush(){Call call;return Blocking()?S_OK:RealOleFlush();}
HRESULT WINAPI OleCurrent(IDataObject* object){Call call;return Blocking()?S_FALSE:RealOleCurrent(object);}
} // namespace

void Initialize(std::atomic<LONG>* calls) noexcept {
    activeCalls=calls;
    // Built-in Edit calls these zero-argument system stubs directly when
    // finishing a copy. Redirect them as well as the public user32 wrappers.
    HMODULE win32u=GetModuleHandleW(L"win32u.dll");
    if(win32u && !RealNativeClose) {
        RealNativeClose=reinterpret_cast<NativeBool>(GetProcAddress(win32u,"NtUserCloseClipboard"));
        RealNativeEmpty=reinterpret_cast<NativeBool>(GetProcAddress(win32u,"NtUserEmptyClipboard"));
        RealNativeAvailable=reinterpret_cast<decltype(RealNativeAvailable)>(GetProcAddress(win32u,"NtUserIsClipboardFormatAvailable"));
        RealNativeEnum=reinterpret_cast<decltype(RealNativeEnum)>(GetProcAddress(win32u,"NtUserEnumClipboardFormats"));
        RealNativeCount=reinterpret_cast<decltype(RealNativeCount)>(GetProcAddress(win32u,"NtUserCountClipboardFormats"));
        RealNativePriority=reinterpret_cast<decltype(RealNativePriority)>(GetProcAddress(win32u,"NtUserGetPriorityClipboardFormat"));
    }
}
bool Blocking() noexcept {return gate.load(std::memory_order_acquire);}
DWORD Diagnostics() noexcept {
#ifdef CLIP_TEST_EXPORTS
    return diagnostics.load();
#else
    return 0;
#endif
}
void Fault() noexcept {Lock lock;Quarantine(clip::kPrivateInvalidData);}
void Poll() noexcept {
    Lock lock;if(!session || scopes)return;
    LONG state=clip::PrivateState(session);
    if(state==clip::kPrivateCancelledBeforeInput){ReleaseSession();return;}
    if(state==clip::kPrivateCancelled || GetTickCount64()>session->deadline) {
        // A request cancelled before the controller commits to sending input is
        // safe to discard. Once input may be queued, never reopen real clipboard.
        if(InterlockedCompareExchange(&session->state,clip::kPrivateCancelledBeforeInput,
            clip::kPrivateReady)==clip::kPrivateReady){ReleaseSession();return;}
        Quarantine(clip::kPrivateTimedOut);
    }
}
bool CanDetach() noexcept {
    Poll();Lock lock;
    if(session && !scopes && InterlockedCompareExchange(&session->state,
        clip::kPrivateCancelledBeforeInput,clip::kPrivateReady)==clip::kPrivateReady)
        ReleaseSession();
    // Shutdown can arrive before the timeout. Drop the shared secret now while
    // retaining the guard for any input or writes already queued in the host.
    if(session)Quarantine(clip::kPrivateTimedOut);
    return !gate.load() && liveObjects.load() == 0;
}
void Arm(const std::wstring& name) noexcept {
    try {
        if(name.size()>128 || name.compare(0,wcslen(clip::kPrivateClipPrefix),clip::kPrivateClipPrefix))return;
        HANDLE h=OpenFileMappingW(FILE_MAP_READ|FILE_MAP_WRITE,FALSE,name.c_str());if(!h)return;
        auto* s=static_cast<clip::PrivateClipSession*>(MapViewOfFile(h,FILE_MAP_READ|FILE_MAP_WRITE,0,0,sizeof(clip::PrivateClipSession)));
        if(!s){CloseHandle(h);return;}
        Lock lock;
        DWORD pid=0;
        const HWND foreground=reinterpret_cast<HWND>(static_cast<ULONG_PTR>(s->foreground));
        const DWORD frameThread=GetWindowThreadProcessId(foreground,&pid);
        DWORD focusPid=0;
        const DWORD tid=GetWindowThreadProcessId(
            reinterpret_cast<HWND>(static_cast<ULONG_PTR>(s->focus)), &focusPid);
        bool valid=s->magic==clip::kPrivateClipMagic && s->version==clip::kPrivateClipVersion &&
            s->processId==GetCurrentProcessId() && pid==s->processId && focusPid==pid && s->threadId==tid &&
            s->operation<=1 && s->inputTag && s->length<=clip::kPrivateClipMaxChars &&
            s->text[s->length]==0 && s->deadline>GetTickCount64() &&
            s->deadline-GetTickCount64()<=15000 && clip::PrivateState(s)==clip::kPrivateCreated;
        if(!valid || session || scopes) {
            s->error=clip::kPrivateBusy;InterlockedExchange(&s->state,clip::kPrivateFailed);
            UnmapViewOfFile(s);CloseHandle(h);return;
        }
#ifdef CLIP_TEST_EXPORTS
        diagnostics.store(0);
#endif
        mapping=h;session=s;rootThread=frameThread;gate.store(true,std::memory_order_release);
        if(!Target()){s->error=clip::kPrivateWrongTarget;InterlockedExchange(&s->state,clip::kPrivateFailed);ReleaseSession();return;}
        // XAML and other frameworks can deliver keyboard work without calling
        // public DispatchMessage. Observe the tagged input at its actual queue,
        // then enclose the window-procedure call that performs the transaction.
        HMODULE module = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&ObserveInput), &module);
        if (module) {
            hookGeneration.fetch_add(1);
            messageHook = SetWindowsHookExW(WH_GETMESSAGE, ObserveInput, module, s->threadId);
            beforeHook = SetWindowsHookExW(WH_CALLWNDPROC, BeforeWindow, module, s->threadId);
            afterHook = SetWindowsHookExW(WH_CALLWNDPROCRET, AfterWindow, module, s->threadId);
            if (frameThread != s->threadId) {
                rootMessageHook = SetWindowsHookExW(WH_GETMESSAGE, ObserveInput, module, frameThread);
                rootBeforeHook = SetWindowsHookExW(WH_CALLWNDPROC, BeforeWindow, module, frameThread);
                rootAfterHook = SetWindowsHookExW(WH_CALLWNDPROCRET, AfterWindow, module, frameThread);
            }
        }
        if (!messageHook || !beforeHook || !afterHook ||
            (frameThread != s->threadId && (!rootMessageHook || !rootBeforeHook || !rootAfterHook))) {
            s->error=clip::kPrivateUnsupported;InterlockedExchange(&s->state,clip::kPrivateFailed);ReleaseSession();return;
        }
        // A cancelled request must not be resurrected by a delayed pipe command.
        if(InterlockedCompareExchange(&s->state,clip::kPrivateReady,clip::kPrivateCreated)!=clip::kPrivateCreated)
            ReleaseSession();
    } catch (...) {Fault();}
}
bool Open(HWND,BOOL& result) noexcept {
    Record(4);
    if(!Blocking())return false;Lock lock;result=FALSE;
    Record((inputDepth?0x1000:0) | (session && GetCurrentThreadId()==session->threadId?0x2000:0) |
           (GetCurrentThreadId()==rootThread?0x4000:0));
    if(!Inside() || opened){Deny();return true;}
    clipboardThread=GetCurrentThreadId();opened=true;closed=false;used=true;result=TRUE;Record(8);return true;
}
bool Close(BOOL& result) noexcept {
    Record(128);
    if(!Blocking())return false;Lock lock;result=FALSE;
    if(!Inside() || !opened || GetCurrentThreadId()!=clipboardThread){Deny();return true;}
    opened=false;closed=true;result=TRUE;
    // Frameworks can finish the clipboard transaction outside DispatchMessage
    // (e.g. XAML pre-translation). CloseClipboard is the completion boundary
    // there; scoped message/OLE handlers keep the session until they return.
    if(!scopes)Finish(true);
    return true;
}
bool Empty(BOOL& result) noexcept {
    if(!Blocking())return false;Lock lock;result=FALSE;
    if(!Inside() || !opened || GetCurrentThreadId()!=clipboardThread || session->operation!=0){Deny();return true;}
    ClearHandles();SecureZeroMemory(session->text,sizeof(session->text));session->length=0;
    unicode=false;result=TRUE;return true;
}
bool Get(UINT format,HANDLE& result) noexcept {
    Record(32);
    if(!Blocking())return false;result=nullptr;
    try {Lock lock;if(!Inside() || !opened || GetCurrentThreadId()!=clipboardThread || session->operation!=1){Deny();return true;}
        result=TextHandle(format);if(!result)SetLastError(ERROR_NOT_SUPPORTED);
    }catch(...){Fault();}return true;
}
bool Set(UINT format,HANDLE memory,HANDLE& result) noexcept {
    Record(16);
    if(!Blocking())return false;result=nullptr;
    try {
        Lock lock;if(!Inside() || !opened || GetCurrentThreadId()!=clipboardThread || session->operation!=0){Deny();return true;}
        if(format!=CF_UNICODETEXT && format!=CF_TEXT && format!=CF_OEMTEXT){SetLastError(ERROR_NOT_SUPPORTED);return true;}
        if(!memory){Fail(clip::kPrivateUnsupported);SetLastError(ERROR_NOT_SUPPORTED);return true;}
        if(owned.size()>=16){Fail(clip::kPrivateTooLarge);return true;}
        if(!Capture(format,static_cast<HGLOBAL>(memory)))return true;
        if(std::find(owned.begin(),owned.end(),memory)==owned.end())owned.push_back(static_cast<HGLOBAL>(memory));
        result=memory;
    }catch(...){Fault();}return true;
}
bool Attach(bool install) noexcept {
    bool ok=true;
#define PRIVATE_DETOUR(real, hook) do { LONG e=install?DetourAttach(reinterpret_cast<PVOID*>(&(real)),reinterpret_cast<PVOID>(hook)):DetourDetach(reinterpret_cast<PVOID*>(&(real)),reinterpret_cast<PVOID>(hook)); if(e!=NO_ERROR)ok=false; } while(0)
    PRIVATE_DETOUR(RealDispatchW,DispatchW); PRIVATE_DETOUR(RealDispatchA,DispatchA);
    PRIVATE_DETOUR(RealTranslateMessage,Translate);
    PRIVATE_DETOUR(RealTranslateW,TranslateW); PRIVATE_DETOUR(RealTranslateA,TranslateA);
    PRIVATE_DETOUR(RealDialogW,DialogW); PRIVATE_DETOUR(RealDialogA,DialogA);
    PRIVATE_DETOUR(RealAvailable,Available); PRIVATE_DETOUR(RealEnum,Enum);
    PRIVATE_DETOUR(RealCount,Count); PRIVATE_DETOUR(RealPriority,Priority);
    PRIVATE_DETOUR(RealOwner,Owner); PRIVATE_DETOUR(RealOpenWindow,OpenWindow);
    PRIVATE_DETOUR(RealOleSet,OleSet); PRIVATE_DETOUR(RealOleGet,OleGet);
    PRIVATE_DETOUR(RealOleFlush,OleFlush); PRIVATE_DETOUR(RealOleCurrent,OleCurrent);
    if(RealNativeClose)PRIVATE_DETOUR(RealNativeClose,NativeClose);
    if(RealNativeEmpty)PRIVATE_DETOUR(RealNativeEmpty,NativeEmpty);
    if(RealNativeAvailable)PRIVATE_DETOUR(RealNativeAvailable,NativeAvailable);
    if(RealNativeEnum)PRIVATE_DETOUR(RealNativeEnum,NativeEnum);
    if(RealNativeCount)PRIVATE_DETOUR(RealNativeCount,NativeCount);
    if(RealNativePriority)PRIVATE_DETOUR(RealNativePriority,NativePriority);
#undef PRIVATE_DETOUR
    return ok;
}
} // namespace privateclip
