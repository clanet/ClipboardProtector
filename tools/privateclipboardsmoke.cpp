#include "../app/privateclipboard.h"
#include "../common/privateclip.h"
#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <ole2.h>
#include <string>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <thread>
#include <atomic>
namespace {
constexpr UINT kPrepare=WM_APP+100, kStatus=WM_APP+101;
thread_local HWND source,target,rich,custom,password;
using ArmFn=BOOL(*)(const wchar_t*); using BlockingFn=BOOL(*)();
ArmFn arm=nullptr; BlockingFn blocking=nullptr;
void (*pollRace)(HANDLE,HANDLE)=nullptr;
HANDLE raceEntered=nullptr,raceResume=nullptr;
void (*startWorker)()=nullptr;
void (*shutdownWorker)()=nullptr;
long (*lifecycle)()=nullptr;
DWORD (*registeredHooks)()=nullptr;
DWORD (*diagnostics)()=nullptr;
thread_local int behavior=0,copyKeys=0,pasteKeys=0,lateBlocked=0;
thread_local std::wstring typed;
const wchar_t* sample=L"私有文字 \xD83C\xDF0D";
const wchar_t* multiline=L"line1\r\n第二行\tend\r\n";
void Check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
HGLOBAL RawMemory(const void* data,size_t bytes){HGLOBAL h=GlobalAlloc(GMEM_MOVEABLE,bytes);Check(h!=nullptr,"allocate fixture bytes");void* p=GlobalLock(h);Check(p!=nullptr,"lock fixture bytes");memcpy(p,data,bytes);GlobalUnlock(h);return h;}
HGLOBAL TextMemory(const wchar_t* text){size_t bytes=(wcslen(text)+1)*sizeof(wchar_t);HGLOBAL memory=GlobalAlloc(GMEM_MOVEABLE,bytes);void* data=GlobalLock(memory);memcpy(data,text,bytes);GlobalUnlock(memory);return memory;}
LRESULT CALLBACK EditProc(HWND h,UINT message,WPARAM wp,LPARAM lp,UINT_PTR,DWORD_PTR){
    if(message==WM_KEYDOWN && (GetKeyState(VK_CONTROL)&0x8000)){if(wp=='C')++copyKeys;if(wp=='V')++pasteKeys;}
    return DefSubclassProc(h,message,wp,lp);
}
LRESULT CALLBACK CustomProc(HWND h,UINT message,WPARAM wp,LPARAM lp){
    if(message==WM_KEYDOWN && (GetKeyState(VK_CONTROL)&0x8000)){
        if(wp=='C'){
            ++copyKeys;if(behavior==3){SetTimer(h,2,8500,nullptr);return 0;}
            if(behavior==7||behavior==8){
                if(OpenClipboard(h)){EmptyClipboard();LCID locale=0x0419;const char bytes[]="\xCF\xF0\xE8\xE2\xE5\xF2";
                    auto putLocale=[&]{HGLOBAL m=RawMemory(&locale,sizeof(locale));if(!SetClipboardData(CF_LOCALE,m))GlobalFree(m);};
                    if(behavior==7)putLocale();HGLOBAL m=RawMemory(bytes,sizeof(bytes));if(!SetClipboardData(CF_TEXT,m))GlobalFree(m);if(behavior==8)putLocale();CloseClipboard();}
                return 0;
            }
            if(OpenClipboard(h)){EmptyClipboard();if(behavior==2)SetClipboardData(CF_UNICODETEXT,nullptr);
                else{std::wstring value=behavior==5?std::wstring(clip::PrivateClipboard::kMaxCharacters,L'x'):
                    behavior==6?std::wstring(clip::PrivateClipboard::kMaxCharacters+1,L'x'):sample;
                    HGLOBAL m=TextMemory(value.c_str());if(!SetClipboardData(CF_UNICODETEXT,m))GlobalFree(m);}CloseClipboard();}
            return 0;
        }
        if(wp=='V'){
            ++pasteKeys;
            if(behavior==4){
                IDataObject* object=nullptr;
                if(SUCCEEDED(OleGetClipboard(&object))&&object){FORMATETC f={CF_UNICODETEXT,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};STGMEDIUM m={};
                    if(SUCCEEDED(object->GetData(&f,&m))){auto* p=static_cast<wchar_t*>(GlobalLock(m.hGlobal));if(p){typed=p;GlobalUnlock(m.hGlobal);}ReleaseStgMedium(&m);}object->Release();}
            }else if(IsClipboardFormatAvailable(CF_UNICODETEXT) && OpenClipboard(h)){
                UINT formats[]={CF_DIB,CF_UNICODETEXT};
                if(CountClipboardFormats()==4&&EnumClipboardFormats(0)==CF_UNICODETEXT&&EnumClipboardFormats(CF_UNICODETEXT)==CF_TEXT&&GetPriorityClipboardFormat(formats,2)==CF_UNICODETEXT){
                    HGLOBAL m=GetClipboardData(CF_UNICODETEXT);auto* p=static_cast<wchar_t*>(GlobalLock(m));if(p){typed=p;GlobalUnlock(m);}}
                CloseClipboard();
            }return 0;
        }
    }
    if(message==WM_TIMER){KillTimer(h,2);if(!OpenClipboard(h))++lateBlocked;else CloseClipboard();return 0;}
    if(message==WM_GETTEXT){size_t count=std::min<size_t>(typed.size(),wp?wp-1:0);if(wp){memcpy(reinterpret_cast<void*>(lp),typed.data(),count*sizeof(wchar_t));reinterpret_cast<wchar_t*>(lp)[count]=0;}return count;}
    if(message==WM_GETTEXTLENGTH)return static_cast<LRESULT>(typed.size());
    return DefWindowProcW(h,message,wp,lp);
}
LRESULT CALLBACK FixtureProc(HWND h,UINT message,WPARAM wp,LPARAM lp){
    if(message==WM_CREATE){HINSTANCE instance=GetModuleHandleW(nullptr);
        source=CreateWindowW(L"Edit",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE,10,10,450,80,h,nullptr,instance,nullptr);
        target=CreateWindowW(L"Edit",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE,10,100,450,80,h,nullptr,instance,nullptr);
        rich=CreateWindowW(MSFTEDIT_CLASS,L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE,10,190,450,80,h,nullptr,instance,nullptr);
        custom=CreateWindowW(L"PrivateClipboardInput",L"",WS_CHILD|WS_VISIBLE,10,280,450,30,h,nullptr,instance,nullptr);
        password=CreateWindowW(L"Edit",L"fictional-password",WS_CHILD|WS_VISIBLE|ES_PASSWORD,10,320,450,30,h,nullptr,instance,nullptr);
        if(!source||!target||!rich||!custom||!password)return -1;
        for(HWND edit:{source,target,rich,password})SetWindowSubclass(edit,EditProc,1,0);return 0;
    }
    if(message==WM_COPYDATA){auto* data=reinterpret_cast<COPYDATASTRUCT*>(lp);
        if(data&&data->dwData==1&&data->cbData>=sizeof(wchar_t)&&data->cbData<=256&&static_cast<const wchar_t*>(data->lpData)[data->cbData/sizeof(wchar_t)-1]==0)
            return arm?arm(static_cast<const wchar_t*>(data->lpData)):FALSE;return FALSE;
    }
    if(message==kStatus){if(wp==1)return copyKeys;if(wp==2)return pasteKeys;if(wp==3)return lateBlocked;if(wp==4)return diagnostics?diagnostics():0;
        if(wp==5){if(!pollRace)return FALSE;ResetEvent(raceEntered);ResetEvent(raceResume);pollRace(raceEntered,raceResume);return TRUE;}
        if(wp==6){if(shutdownWorker)shutdownWorker();return shutdownWorker!=nullptr;}
        if(wp==7)return lifecycle?lifecycle():-1;
        if(wp==8){if(startWorker)startWorker();return startWorker!=nullptr;}
        if(wp==9)return registeredHooks?registeredHooks():-1;
        return blocking?blocking():FALSE;}
    if(message==kPrepare){HWND focus=source;behavior=0;
        if(wp==1){std::wstring value=L"AA"+std::wstring(sample)+L"ZZ";SetWindowTextW(source,value.c_str());SendMessageW(source,EM_SETSEL,2,value.size()-2);}
        if(wp==2){focus=target;SetWindowTextW(target,L"left OLD right");SendMessageW(target,EM_SETSEL,5,8);}
        if(wp==3||wp==4){focus=rich;SetWindowTextW(rich,wp==3?sample:multiline);SendMessageW(rich,EM_SETSEL,0,-1);}
        if(wp==5||wp==6||wp==7||wp==8||wp==10){focus=custom;typed.clear();behavior=wp==6?2:wp==7?3:wp==8?4:0;}
        if(wp==9){focus=password;SendMessageW(password,EM_SETSEL,0,-1);}
        if(wp==11||wp==12){focus=custom;typed.clear();behavior=wp==11?5:6;}
        if(wp==13||wp==14){focus=custom;typed.clear();behavior=wp==13?7:8;}
        SetFocus(focus);return reinterpret_cast<LRESULT>(focus);
    }
    if(message==WM_DESTROY){PostQuitMessage(0);return 0;}if(message==WM_TIMER){DestroyWindow(h);return 0;}
    return DefWindowProcW(h,message,wp,lp);
}
void Pump(){MSG msg;while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);}}
std::wstring Read(HWND edit){wchar_t text[1024]={};SendMessageW(edit,WM_GETTEXT,_countof(text),reinterpret_cast<LPARAM>(text));return text;}
bool Wait(clip::PrivateClipboard& clipboard){auto deadline=GetTickCount64()+12000;std::wstring status;bool success=false;
    while(GetTickCount64()<deadline){Pump();if(clipboard.TakeResult(status,success)){
        if(!success){int n=WideCharToMultiByte(CP_UTF8,0,status.data(),static_cast<int>(status.size()),nullptr,0,nullptr,nullptr);std::string utf8(n,0);WideCharToMultiByte(CP_UTF8,0,status.data(),static_cast<int>(status.size()),utf8.data(),n,nullptr,nullptr);std::cout<<utf8<<'\n';}return success;}Sleep(10);}
    throw std::runtime_error("worker timeout");
}
struct Fixture{PROCESS_INFORMATION process={};HWND window=nullptr,second=nullptr,previous=GetForegroundWindow();
    ~Fixture(){if(second)PostMessageW(second,WM_CLOSE,0,0);if(window)PostMessageW(window,WM_CLOSE,0,0);if(process.hProcess){WaitForSingleObject(process.hProcess,3000);CloseHandle(process.hThread);CloseHandle(process.hProcess);}if(IsWindow(previous))SetForegroundWindow(previous);}};
struct ClipboardLock{bool held=false;~ClipboardLock(){if(held)CloseClipboard();}};
struct ReadyCancellation {
    HANDLE mapping=nullptr,entered=nullptr,resume=nullptr;
    clip::PrivateClipSession* session=nullptr;
    std::wstring name;
    ~ReadyCancellation(){if(resume)SetEvent(resume);if(session)UnmapViewOfFile(session);for(HANDLE h:{mapping,entered,resume})if(h)CloseHandle(h);}
    void Create(DWORD pid,HWND window,HWND focus){
        name=std::wstring(clip::kPrivateClipPrefix)+L"Race."+std::to_wstring(GetCurrentProcessId())+L"."+std::to_wstring(GetTickCount64());
        mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,sizeof(clip::PrivateClipSession),name.c_str());Check(mapping!=nullptr,"create ready-race mapping");
        session=static_cast<clip::PrivateClipSession*>(MapViewOfFile(mapping,FILE_MAP_READ|FILE_MAP_WRITE,0,0,sizeof(clip::PrivateClipSession)));Check(session!=nullptr,"map ready-race session");
        ZeroMemory(session,sizeof(*session));session->magic=clip::kPrivateClipMagic;session->version=clip::kPrivateClipVersion;session->processId=pid;
        session->threadId=GetWindowThreadProcessId(focus,nullptr);session->inputTag=0x4a31;session->foreground=reinterpret_cast<ULONG_PTR>(window);session->focus=reinterpret_cast<ULONG_PTR>(focus);session->deadline=GetTickCount64()+1000;
        const std::wstring suffix=std::to_wstring(pid);
        entered=OpenEventW(SYNCHRONIZE,FALSE,(L"Local\\PrivateClipboardTest.RaceEntered."+suffix).c_str());
        resume=OpenEventW(EVENT_MODIFY_STATE,FALSE,(L"Local\\PrivateClipboardTest.RaceResume."+suffix).c_str());
        Check(entered&&resume,"open ready-race events");
    }
};
}
int wmain(int argc,wchar_t** argv){
    if(argc==3&&wcscmp(argv[1],L"--fixture")==0){
        OleInitialize(nullptr);LoadLibraryW(L"Msftedit.dll");std::wstring suffix=std::to_wstring(GetCurrentProcessId());
        std::wstring mutexName=L"Local\\PrivateClipboardTest.Controller."+suffix,stopName=L"Local\\PrivateClipboardTest.Stop."+suffix,pipeName=L"\\\\.\\pipe\\PrivateClipboardTest.NoController."+suffix;
        SetEnvironmentVariableW(L"CLIP_TEST_CONTROLLER_MUTEX",mutexName.c_str());SetEnvironmentVariableW(L"CLIP_TEST_STOP_EVENT",stopName.c_str());SetEnvironmentVariableW(L"CLIP_TEST_PIPE_NAME",pipeName.c_str());
        CreateMutexW(nullptr,TRUE,mutexName.c_str());CreateEventW(nullptr,TRUE,FALSE,stopName.c_str());
        HMODULE dll=LoadLibraryW(argv[2]);if(!dll)return 2;
        auto start=reinterpret_cast<void(*)()>(GetProcAddress(dll,"ClipHookStartForTest"));auto debug=reinterpret_cast<void(*)(long*)>(GetProcAddress(dll,"ClipHookDebug"));
        arm=reinterpret_cast<ArmFn>(GetProcAddress(dll,"ClipHookPrivateArmForTest"));blocking=reinterpret_cast<BlockingFn>(GetProcAddress(dll,"ClipHookPrivateBlockingForTest"));if(!start||!debug||!arm||!blocking)return 3;
        diagnostics=reinterpret_cast<DWORD(*)()>(GetProcAddress(dll,"ClipHookPrivateDiagnosticsForTest"));
        pollRace=reinterpret_cast<void(*)(HANDLE,HANDLE)>(GetProcAddress(dll,"ClipHookPrivatePollRaceForTest"));
        startWorker=start;shutdownWorker=reinterpret_cast<void(*)()>(GetProcAddress(dll,"ClipHookShutdownForTest"));
        lifecycle=reinterpret_cast<long(*)()>(GetProcAddress(dll,"ClipHookLifecycleForTest"));
        registeredHooks=reinterpret_cast<DWORD(*)()>(GetProcAddress(dll,"ClipHookPrivateRegisteredHooksForTest"));
        raceEntered=CreateEventW(nullptr,TRUE,FALSE,(L"Local\\PrivateClipboardTest.RaceEntered."+suffix).c_str());
        raceResume=CreateEventW(nullptr,TRUE,FALSE,(L"Local\\PrivateClipboardTest.RaceResume."+suffix).c_str());
        start();long state[8]={};for(int i=0;i<500;++i){debug(state);if(state[1])break;Sleep(10);}if(!state[1])return 4;
        WNDCLASSW input={};input.lpfnWndProc=CustomProc;input.hInstance=GetModuleHandleW(nullptr);input.lpszClassName=L"PrivateClipboardInput";RegisterClassW(&input);
        WNDCLASSW fixture={};fixture.lpfnWndProc=FixtureProc;fixture.hInstance=input.hInstance;fixture.lpszClassName=L"PrivateClipboardFixture";RegisterClassW(&fixture);
        std::atomic<HWND> other{nullptr};
        std::thread otherGui([&]{HWND w=CreateWindowW(fixture.lpszClassName,L"PrivateClipboardFixture.Second",WS_OVERLAPPEDWINDOW|WS_VISIBLE,600,60,500,410,nullptr,nullptr,fixture.hInstance,nullptr);
            other.store(w);if(w){SetTimer(w,1,90000,nullptr);MSG m;while(GetMessageW(&m,nullptr,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}}});
        HWND window=CreateWindowW(fixture.lpszClassName,L"Private clipboard test (fictional text)",WS_OVERLAPPEDWINDOW|WS_VISIBLE,60,60,500,410,nullptr,nullptr,fixture.hInstance,nullptr);
        if(window){SetTimer(window,1,90000,nullptr);MSG message;while(GetMessageW(&message,nullptr,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}}
        if(HWND w=other.load())PostMessageW(w,WM_CLOSE,0,0);otherGui.join();CloseHandle(raceEntered);CloseHandle(raceResume);return window?0:5;
    }
    if(argc!=2 && argc!=3)return 2;
    try{Fixture fixture;wchar_t executable[MAX_PATH]={};GetModuleFileNameW(nullptr,executable,MAX_PATH);
        const wchar_t* fixtureExecutable=argc==3?argv[2]:executable;
        std::wstring command=L"\""+std::wstring(fixtureExecutable)+L"\" --fixture \""+argv[1]+L"\"";STARTUPINFOW startup={sizeof(startup)};
        Check(CreateProcessW(fixtureExecutable,command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&fixture.process)!=FALSE,"start fixture");AllowSetForegroundWindow(fixture.process.dwProcessId);WaitForInputIdle(fixture.process.hProcess,7000);
        for(int i=0;i<700&&!fixture.window;++i){HWND w=FindWindowW(L"PrivateClipboardFixture",L"Private clipboard test (fictional text)");DWORD pid=0;GetWindowThreadProcessId(w,&pid);if(pid==fixture.process.dwProcessId)fixture.window=w;Sleep(10);}Check(fixture.window!=nullptr,"find injected fixture");
        for(int i=0;i<700&&!fixture.second;++i){HWND w=FindWindowW(L"PrivateClipboardFixture",L"PrivateClipboardFixture.Second");DWORD pid=0;GetWindowThreadProcessId(w,&pid);if(pid==fixture.process.dwProcessId)fixture.second=w;Sleep(10);}Check(fixture.second!=nullptr,"find second GUI thread fixture");
        // Lock without reading/writing real clipboard; a missed detour cannot overwrite user data.
        ClipboardLock systemLock;for(int i=0;i<100&&!systemLock.held;++i){systemLock.held=OpenClipboard(nullptr)!=FALSE;if(!systemLock.held)Sleep(10);}Check(systemLock.held,"hold real clipboard against accidental test writes");
        const DWORD sequence=GetClipboardSequenceNumber();
        HWND activeWindow=fixture.window;
        auto prepare=[&](int action){
            for(int i=0;i<10;++i){SetForegroundWindow(activeWindow);Sleep(100);if(GetForegroundWindow()==activeWindow)break;}
            Check(GetForegroundWindow()==activeWindow,"test focus was stolen");
            return reinterpret_cast<HWND>(SendMessageW(activeWindow,kPrepare,action,0));
        };
        auto armTarget=[&](DWORD pid,const std::wstring& name){if(pid!=fixture.process.dwProcessId)return false;COPYDATASTRUCT data={1,static_cast<DWORD>((name.size()+1)*sizeof(wchar_t)),const_cast<wchar_t*>(name.c_str())};DWORD_PTR result=0;return SendMessageTimeoutW(fixture.window,WM_COPYDATA,0,reinterpret_cast<LPARAM>(&data),SMTO_ABORTIFHUNG|SMTO_BLOCK,2000,&result)&&result;};
        clip::PrivateClipboard clipboard;using Operation=clip::PrivateClipboard::Operation;
        auto perform=[&](Operation op){Check(clipboard.Start(op,activeWindow,nullptr,WM_APP+20,armTarget),"start operation");bool ok=Wait(clipboard);if(!ok)std::cout<<"diagnostics="<<SendMessageW(activeWindow,kStatus,4,0)<<" keys="<<SendMessageW(activeWindow,kStatus,1,0)<<'\n';return ok;};
        prepare(1);Check(clipboard.Start(Operation::copy,fixture.window,nullptr,WM_APP+20),"start unready");Check(!Wait(clipboard)&&SendMessageW(fixture.window,kStatus,1,0)==0,"unready sends no Ctrl+C");
        Check(clipboard.Start(Operation::copy,fixture.window,nullptr,WM_APP+20,[](DWORD,const std::wstring&){return true;}),"start missing ACK");Check(!Wait(clipboard)&&SendMessageW(fixture.window,kStatus,1,0)==0,"missing ready ACK sends no Ctrl+C");
        {ReadyCancellation race;HWND focus=prepare(1);race.Create(fixture.process.dwProcessId,activeWindow,focus);
            Check(SendMessageW(activeWindow,kStatus,5,0)!=0,"install ready-race barrier");Check(armTarget(fixture.process.dwProcessId,race.name),"arm ready-race session");
            Check(clip::PrivateState(race.session)==clip::kPrivateReady,"ready-race session acknowledged");
            Check(WaitForSingleObject(race.entered,5000)==WAIT_OBJECT_0,"poll reaches ready timeout CAS");
            Check(InterlockedCompareExchange(&race.session->state,clip::kPrivateCancelledBeforeInput,clip::kPrivateReady)==clip::kPrivateReady,"controller cancels before input");
            SetEvent(race.resume);for(int i=0;i<500&&SendMessageW(activeWindow,kStatus,0,0);++i)Sleep(10);
            Check(!SendMessageW(activeWindow,kStatus,0,0),"CAS-lost pre-input cancellation releases without quarantine");}
        prepare(1);Check(perform(Operation::copy)&&clipboard.HasText(),"native Ctrl+C intercepted");Check(!SendMessageW(fixture.window,kStatus,0,0),"successful input scope restores normal clipboard path");
        HWND targetEdit=prepare(2);Check(perform(Operation::paste)&&Read(targetEdit)==L"left "+std::wstring(sample)+L" right","native Ctrl+V replaces selected text");
        for(int action:{3,4}){prepare(action);Check(perform(Operation::copy),"RichEdit native copy");targetEdit=prepare(2);Check(perform(Operation::paste)&&Read(targetEdit)==L"left "+std::wstring(action==3?sample:multiline)+L" right","RichEdit Unicode and multiline exact paste");}
        HWND customEdit=prepare(10);Check(perform(Operation::paste)&&Read(customEdit)==multiline,"format queries see only private text");customEdit=prepare(8);Check(perform(Operation::paste)&&Read(customEdit)==multiline,"OLE receives private text object");
        for(int i=0;i<16;++i){activeWindow=(i%2)?fixture.window:fixture.second;prepare(1);Check(perform(Operation::copy),"copy across cached GUI-thread hooks");
            activeWindow=(i%2)?fixture.second:fixture.window;HWND edit=prepare(2);Check(perform(Operation::paste)&&Read(edit)==L"left "+std::wstring(sample)+L" right","paste across cached GUI-thread hooks");}
        activeWindow=fixture.window;
        for(int action:{13,14}){prepare(action);Check(perform(Operation::copy),"ANSI copy accepts locale in either format order");
            HWND edit=prepare(10);Check(perform(Operation::paste)&&Read(edit)==L"Привет","private ANSI locale decodes exact Unicode");}
        Check(SendMessageW(fixture.window,kStatus,9,0)==6,"sessions reuse exactly three hooks per GUI thread");
        Check(SendMessageW(fixture.window,kStatus,6,0)!=0,"request idle private-hook shutdown");
        for(int i=0;i<700&&(SendMessageW(fixture.window,kStatus,7,0)&1);++i)Sleep(10);
        Check(!(SendMessageW(fixture.window,kStatus,7,0)&1)&&SendMessageW(fixture.window,kStatus,9,0)==0,"idle shutdown unregisters every cached hook");
        for(int i=0;i<500;++i){SendMessageW(fixture.window,kStatus,8,0);if(SendMessageW(fixture.window,kStatus,7,0)&1)break;Sleep(10);}
        prepare(1);Check(perform(Operation::copy),"private session restarts after complete idle retirement");
        prepare(9);const auto keys=SendMessageW(fixture.window,kStatus,1,0);Check(!perform(Operation::copy)&&!clipboard.HasText()&&SendMessageW(fixture.window,kStatus,1,0)==keys,"password copy rejected before key send");
        prepare(5);Check(perform(Operation::copy),"custom application copy");clipboard.Clear();Check(!clipboard.HasText()&&!perform(Operation::paste),"clear prevents stale paste");
        prepare(11);Check(perform(Operation::copy),"maximum text length accepted");customEdit=prepare(10);
        Check(perform(Operation::paste)&&SendMessageW(customEdit,WM_GETTEXTLENGTH,0,0)==static_cast<LRESULT>(clip::PrivateClipboard::kMaxCharacters),"maximum length paste intact");
        prepare(12);Check(!perform(Operation::copy)&&!clipboard.HasText(),"oversized text rejected and clears prior memory");
        prepare(6);Check(!perform(Operation::copy)&&!clipboard.HasText(),"delayed rendering rejected");Check(SendMessageW(fixture.window,kStatus,0,0)!=0,"failed private transaction stays isolated");
        prepare(5);Check(perform(Operation::copy),"private retry works inside quarantine");Check(SendMessageW(fixture.window,kStatus,0,0)!=0,"retry never releases quarantine");
        prepare(7);Check(!perform(Operation::copy),"asynchronous copy not mistaken for success");Sleep(900);Check(SendMessageW(fixture.window,kStatus,3,0)>0,"late clipboard access blocked after timeout");
        Check(GetClipboardSequenceNumber()==sequence,"system clipboard unchanged");clipboard.Stop();std::cout<<"Private hooked clipboard: ready handshake, native/RichEdit/OLE, formats, password, clear, delayed and async failure isolation passed.\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
