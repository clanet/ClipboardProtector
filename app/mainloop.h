#pragma once
#include <string>

namespace clip {
bool CreateMainWindow();          // 创建主窗口（失败弹错误框）
void RunMessageLoop();            // 标准消息循环
void RequestExit();               // 清理托盘并退出
bool SetGlobalInjectionEnabled(bool enabled, std::wstring& error);
bool IsGlobalInjectionEnabled();
void StopProtectionForExit(); // 后台清理；窗口由 UI 线程在完成后销毁
bool IsTargetedInjectionMode();
DWORD TargetedInjectionPid();
bool StartSingleProcessTest(DWORD processId, std::wstring& error);
bool StartPreparedSingleProcessTest(DWORD processId, std::wstring& error);
bool StopSingleProcessTest(std::wstring& error);
}
