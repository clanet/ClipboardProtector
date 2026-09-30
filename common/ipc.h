#pragma once
// 命名管道协议：Hook.dll(客户端) <-> 主程序(服务端)。
// 所有整数小端，消息由固定头 + 变长字段组成，字段前有长度。
#include <windows.h>
#include <cstddef>
#include <cstring>
#include <string>
#include "crypto.h"
#include "eventtext.h"

namespace clip {

// Every frame starts with a type and this version byte.  Keeping the version
// in the wire format makes incompatible clients fail closed instead of
// interpreting a newer frame as an older one.
constexpr BYTE kIpcVersion = 1;
// Every message is a byte-stream frame: type, version, payload length, payload.
// The length lets both sides distinguish an ACK from queued event bytes.
constexpr DWORD kMaxClipboardSnapshotBytes = 1u << 20;
// Event frames may carry one bounded image or file-list snapshot plus metadata.
constexpr DWORD kIpcMaxPayload = kMaxClipboardSnapshotBytes + (128u << 10);
constexpr size_t kIpcFrameHeaderSize = 6;
// Extended rule snapshots retain protocol version 1 and use a payload marker
// so the rebuilt DLL can still accept legacy test/controller rule frames.
constexpr DWORD kRulePayloadMarker = 0x32524C43; // "CLR2"
constexpr DWORD kStateAckCapabilityMarker = 0x32504143; // "CAP2"
// CLR3 adds an independent per-rule notification byte. CAP3 lets the server
// select it without sending an incompatible snapshot to an older DLL.
constexpr DWORD kRulePayloadMarkerV3 = 0x33524C43; // "CLR3"
constexpr DWORD kStateAckCapabilityMarkerV3 = 0x33504143; // "CAP3"
// CLR4 adds per-rule main-window log-list visibility.
constexpr DWORD kRulePayloadMarkerV4 = 0x34524C43; // "CLR4"
// CAP4 indicates that the DLL also understands the shared Crypto guard state.
constexpr DWORD kStateAckCapabilityMarkerV4 = 0x34504143; // "CAP4"
// CAP5 adds the semantic blockchain rule format. Its trailing flags report
// runtime resources rather than only compile-time protocol support.
constexpr DWORD kStateAckCapabilityMarkerV5 = 0x35504143; // "CAP5"
// CAP6 replaces encoding-specific selectors with text/non-text, address, and
// private-key/mnemonic formats and recognizes common registered UTF-8 text.
constexpr DWORD kStateAckCapabilityMarkerV6 = 0x36504143; // "CAP6"
// CAP7 adds a third settings byte carrying the authoritative Crypto switch.
// CAP6 clients must continue receiving the original two-byte settings frame.
constexpr DWORD kStateAckCapabilityMarkerV7 = 0x37504143; // "CAP7"
// CAP8 marks the high hash bit as Crypto-content metadata on event frames.
constexpr DWORD kStateAckCapabilityMarkerV8 = 0x38504143; // "CAP8"
// CAP9 adds bounded in-memory image/file snapshots to extended event frames.
constexpr DWORD kStateAckCapabilityMarkerV9 = 0x39504143; // "CAP9"
// CA10 adds the direct Ctrl+C/Ctrl+V policy and its authorization window.
// Four bytes cannot hold "CAP10", so the marker uses the compact "CA10".
constexpr DWORD kStateAckCapabilityMarkerV10 = 0x30314143; // "CA10"
// CA11 adds the ignore-custom-formats switch as a trailing settings byte.
constexpr DWORD kStateAckCapabilityMarkerV11 = 0x31314143; // "CA11"
// CA12 adds CLR4 rules and a trailing event visibility byte.
constexpr DWORD kStateAckCapabilityMarkerV12 = 0x32314143; // "CA12"
constexpr BYTE kStateAckCryptoMappingAvailable = 0x01;
constexpr BYTE kStateAckPrivateClipboardAvailable = 0x02;
// Negotiated by a trailing settings byte; adds typed event/confirmation labels.
constexpr BYTE kStateAckTextMetadataAvailable = 0x04;
constexpr BYTE kStateAckKnownCapabilityFlags =
    kStateAckCryptoMappingAvailable | kStateAckPrivateClipboardAvailable |
    kStateAckTextMetadataAvailable;
constexpr BYTE kEventNotificationFlag = 0x80;
// The content hash is internal audit metadata. Its high bit marks content that
// the reporting DLL recognized while Crypto protection was enabled.
constexpr unsigned long long kEventCryptoContentFlag = 1ull << 63;

enum ClipboardSnapshotKind : BYTE {
    kSnapshotNone = 0,
    kSnapshotImage = 1,
    kSnapshotFiles = 2,
    kSnapshotTooLarge = 3,
    kSnapshotDiscarded = 4,
};

constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\ClipboardProtector";
constexpr wchar_t kStopEventName[] = L"Local\\ClipboardProtector.HookStop";
constexpr wchar_t kSingleInstanceMutexName[] =
    L"Local\\ClipboardProtector.SingleInstance";
// A targeted injector posts this registered thread message to distinguish a
// new installation from callbacks that are still draining during removal.
constexpr wchar_t kTargetHookStartMessageName[] =
    L"ClipboardProtector.TargetHookStart.v1";
constexpr wchar_t kClipboardSourceMapName[] =
    L"Local\\ClipboardProtector.ClipboardSource.v1";
constexpr wchar_t kCryptoProtectionMapName[] =
    L"Local\\ClipboardProtector.CryptoProtection.v2";
constexpr DWORD kClipboardSourcePathChars = 1024;
constexpr DWORD kCryptoAddressChars = 96;

struct SharedClipboardSource {
    volatile LONG guard = 0;
    DWORD sequence = 0;
    DWORD processId = 0;
    wchar_t processPath[kClipboardSourcePathChars] = {};
};

constexpr DWORD kCryptoProtectionVersion = 2;
struct SharedCryptoAddress {
    DWORD kind = 0;
    wchar_t canonical[kCryptoAddressChars] = {};
};
struct SharedCryptoProtection {
    volatile LONG guard = 0;
    DWORD structureVersion = kCryptoProtectionVersion;
    volatile LONG enabled = 0;
    LONG active = 0;
    DWORD addressCount = 0;
    DWORD writerProcessId = 0;
    DWORD clipboardSequence = 0;
    DWORD reserved = 0;
    ULONGLONG expiresAt = 0;
    SharedCryptoAddress addresses[kMaxProtectedCryptoAddresses] = {};
};

static_assert(offsetof(SharedCryptoProtection, expiresAt) == 32,
              "Shared Crypto state must have the same x86/x64 layout");
static_assert(offsetof(SharedCryptoProtection, addresses) == 40,
              "Shared Crypto state must have the same x86/x64 layout");
static_assert(sizeof(SharedCryptoAddress) == 196 &&
              sizeof(SharedCryptoProtection) == 50216,
              "Shared Crypto state must have the same x86/x64 size");

enum IpcMsgType : BYTE {
    kIpcEvent = 1,   // DLL -> 主程序：剪贴板访问事件
    kIpcRules = 2,   // 主程序 -> DLL：规则快照全量下发
    kIpcPause = 3,   // 主程序 -> DLL：暂停/恢复保护
    kIpcSettings = 4,// 主程序 -> DLL：预览与快捷键访问过滤设置
    kIpcShutdown = 5,// 主程序 -> DLL：停止通信并进入 fail-open
    kIpcStateBegin = 6,// 主程序 -> DLL：完整状态快照开始
    kIpcShutdownAck = 7,// DLL -> 主程序：Detours 已移除且调用清退完成
    kIpcStateAck = 8, // DLL -> 主程序：完整状态已应用，可开始监控
    kIpcRulesExtended = 9, // 主程序 -> 新 DLL：扩展规则快照
    kIpcEventGap = 10, // 新 DLL -> 主程序：无法保留的事件数量
    kIpcConfirmRequest = 11, // DLL -> 主程序：请求用户确认本次访问
    kIpcConfirmResponse = 12, // 主程序 -> DLL：确认结果
    kIpcPrivateClipboard = 13, // 主程序 -> DLL：私有会话映射名称；就绪确认在映射内
};

// kIpcEvent 的操作类型
enum ClipOp : BYTE {
    kOpRead  = 0,    // GetClipboardData
    kOpWrite = 1,    // SetClipboardData
    kOpClear = 2,    // EmptyClipboard
    kOpOpen  = 3,    // OpenClipboard
};

// ---- 序列化辅助：追加定长整数 ----
inline void PutU8(std::string& b, BYTE v)   { b.push_back((char)v); }
inline void PutHeader(std::string& b, BYTE type) {
    PutU8(b, type);
    PutU8(b, kIpcVersion);
}
inline void PutU32(std::string& b, DWORD v) {
    for (int i = 0; i < 4; ++i) b.push_back((char)((v >> (i * 8)) & 0xFF));
}
inline void PutFrame(std::string& b, BYTE type, const std::string& payload = {}) {
    PutHeader(b, type);
    PutU32(b, (DWORD)payload.size());
    b.append(payload);
}
inline void PutU64(std::string& b, unsigned long long v) {
    for (int i = 0; i < 8; ++i) b.push_back((char)((v >> (i * 8)) & 0xFF));
}
// 字符串：U32 字符数 + wchar 数据
inline void PutWStr(std::string& b, const std::wstring& s) {
    PutU32(b, (DWORD)s.size());
    const char* p = reinterpret_cast<const char*>(s.data());
    b.append(p, s.size() * sizeof(wchar_t));
}

enum class IpcFrameResult { incomplete, invalid, complete };

struct IpcFrameView {
    BYTE type = 0;
    const char* payload = nullptr;
    size_t payloadSize = 0;
    size_t consumed = 0;
};

inline IpcFrameResult ParseFrame(const char* data, size_t size,
                                 IpcFrameView& frame) {
    frame = {};
    if (size < kIpcFrameHeaderSize) return IpcFrameResult::incomplete;
    frame.type = static_cast<BYTE>(data[0]);
    if (static_cast<BYTE>(data[1]) != kIpcVersion) {
        frame.consumed = 1;
        return IpcFrameResult::invalid;
    }
    const DWORD length = static_cast<DWORD>(static_cast<BYTE>(data[2])) |
                         (static_cast<DWORD>(static_cast<BYTE>(data[3])) << 8) |
                         (static_cast<DWORD>(static_cast<BYTE>(data[4])) << 16) |
                         (static_cast<DWORD>(static_cast<BYTE>(data[5])) << 24);
    if (length > kIpcMaxPayload) {
        frame.consumed = kIpcFrameHeaderSize;
        return IpcFrameResult::invalid;
    }
    const size_t frameSize = kIpcFrameHeaderSize + static_cast<size_t>(length);
    if (size < frameSize) return IpcFrameResult::incomplete;
    frame.payload = data + kIpcFrameHeaderSize;
    frame.payloadSize = length;
    frame.consumed = frameSize;
    return IpcFrameResult::complete;
}

struct Reader {
    const char* p;
    size_t n;
    bool bad = false;
    bool incomplete = false;
    bool invalid = false;
    Reader(const char* data, size_t len) : p(data), n(len) {}

    bool GetU8(BYTE& v) {
        if (bad) return false;
        if (n < 1) { bad = true; incomplete = true; return false; }
        v = (BYTE)*p++; --n; return true;
    }
    bool GetU32(DWORD& v) {
        if (bad) return false;
        if (n < 4) { bad = true; incomplete = true; return false; }
        v = 0;
        for (int i = 0; i < 4; ++i) v |= (DWORD)(BYTE)p[i] << (i * 8);
        p += 4; n -= 4; return true;
    }
    bool GetU64(unsigned long long& v) {
        if (bad) return false;
        if (n < 8) { bad = true; incomplete = true; return false; }
        v = 0;
        for (int i = 0; i < 8; ++i) v |= (unsigned long long)(BYTE)p[i] << (i * 8);
        p += 8; n -= 8; return true;
    }
    bool GetWStr(std::wstring& s) {
        DWORD chars = 0;
        if (!GetU32(chars)) return false;
        if (chars > 32768) {
            bad = true;
            invalid = true;
            return false;
        }
        const size_t bytes = static_cast<size_t>(chars) * sizeof(wchar_t);
        if (n < bytes) {
            bad = true;
            incomplete = true;
            return false;
        }
        s.resize(chars);
        if (bytes) std::memcpy(s.data(), p, bytes);
        p += bytes;
        n -= bytes;
        return true;
    }
};

struct StateAck {
    unsigned version = 0;
    bool extendedApplied = false;
    BYTE flags = 0;

    bool HasCryptoMapping() const {
        // CAP4 implied readiness; CAP5 introduced an explicit runtime flag.
        return version == 4 || (version >= 5 && (flags & kStateAckCryptoMappingAvailable));
    }
    bool HasTextMetadata() const {
        return version >= 12 && (flags & kStateAckTextMetadataAvailable);
    }
};

inline bool ParseStateAck(const char* data, size_t size, StateAck& result) {
    result = {};
    Reader reader(data, size);
    DWORD marker = 0;
    BYTE applied = 0;
    if (!reader.GetU32(marker) || !reader.GetU8(applied) || applied > 1)
        return false;
    StateAck parsed;
    // Wire markers are not numerically ordered (CAP9 is followed by CA10).
    // Accept only known versions; an unknown marker must not enable features.
    switch (marker) {
    case kStateAckCapabilityMarker: parsed.version = 2; break;
    case kStateAckCapabilityMarkerV3: parsed.version = 3; break;
    case kStateAckCapabilityMarkerV4: parsed.version = 4; break;
    case kStateAckCapabilityMarkerV5: parsed.version = 5; break;
    case kStateAckCapabilityMarkerV6: parsed.version = 6; break;
    case kStateAckCapabilityMarkerV7: parsed.version = 7; break;
    case kStateAckCapabilityMarkerV8: parsed.version = 8; break;
    case kStateAckCapabilityMarkerV9: parsed.version = 9; break;
    case kStateAckCapabilityMarkerV10: parsed.version = 10; break;
    case kStateAckCapabilityMarkerV11: parsed.version = 11; break;
    case kStateAckCapabilityMarkerV12: parsed.version = 12; break;
    default: return false;
    }
    if (parsed.version >= 5 &&
        (!reader.GetU8(parsed.flags) || (parsed.flags & ~kStateAckKnownCapabilityFlags)))
        return false;
    if (reader.n != 0) return false;
    parsed.extendedApplied = applied != 0;
    result = parsed;
    return true;
}

} // namespace clip
