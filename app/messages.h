#pragma once
// 主窗口自定义消息（管道线程 -> UI 线程的封送通道）
#include <windows.h>

namespace clip {
enum : UINT {
    kMsgEvent = WM_APP + 2,     // 仅表示进程内事件队列可消费；不传递裸指针
    kMsgClients = WM_APP + 3,   // wParam = 当前已注入连接数
    kMsgConfirmation = WM_APP + 5, // 新确认请求或已取消请求可供 UI 消费
    kMsgConfirmationDecision = WM_APP + 6, // 确认窗口提交结果
#ifdef CLIP_TEST_OBJECT_NAMES
    kMsgTestClientCount = WM_APP + 8, // 测试构建只读查询
#endif
};
} // namespace clip
