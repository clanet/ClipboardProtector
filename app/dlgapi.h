#pragma once
#include <windows.h>
#include <vector>
#include <functional>
#include "config.h"

namespace clip {

// 打开规则管理对话框；返回 true 表示规则有修改。
bool ShowRulesDialog(HWND owner, std::vector<Rule>& rules);

// 打开单条规则编辑器；返回 true 表示用户确认了规则。
bool ShowRuleEditor(HWND owner, Rule& rule);

// 打开设置对话框；返回 true 表示确认了修改。
bool ShowSettingsDialog(HWND owner, Settings& settings);

void ShowHotkeyDialog(HWND owner, const AppHotkeys& keys,
    const std::function<bool(const AppHotkeys&, std::wstring&)>& apply);

// 选择并预检任意兼容桌面进程的 PID；不在这里执行注入。
bool ShowTargetProcessDialog(HWND owner, DWORD& processId);

} // namespace clip
