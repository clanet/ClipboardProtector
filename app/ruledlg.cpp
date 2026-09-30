#include "i18n.h"
#include "dialog_i18n.h"
#include "dlgapi.h"
#include <commctrl.h>
#include <algorithm>
#include <utility>
#include "app.h"
#include "rules.h"
#include "resource.h"

namespace clip {
namespace {

struct EditCtx { Rule rule; };

static const TextId kDecisionNames[] = {TextId::Allow, TextId::Block, TextId::AskEveryTime};
static const TextId kNotificationNames[] = {TextId::Silent, TextId::TrayNotification};
static const TextId kTypeNames[] = {TextId::ProcessName, TextId::FullPath};
static const TextId kOperationNames[] = {TextId::ReadAndWrite, TextId::ReadOnly, TextId::WriteOnly};
struct FormatOption {
    unsigned char value;
    TextId name;
};
static const FormatOption kFormatOptions[] = {
    {kFormatAny, TextId::AnyFormat},
    {kFormatNonText, TextId::NonText},
    {kFormatText, TextId::Text2},
    {kFormatCryptoAddress, TextId::CryptoAddress},
    {kFormatPrivateKeyMnemonic, TextId::PrivateKeyMnemonic},
};
static const TextId kSourceNames[] = {
    TextId::AnySource, TextId::SourceProcessName, TextId::SourceFullPath,
    TextId::SameProcess2, TextId::DifferentProcess, TextId::UnknownSource2,
};
static const TextId kTimeoutNames[] = {TextId::BlockAccess, TextId::AllowAccess};

template <size_t N>
void FillCombo(HWND dialog, int id, const TextId (&items)[N]) {
    for (TextId item : items)
        SendDlgItemMessageW(dialog, id, CB_ADDSTRING, 0,
                            reinterpret_cast<LPARAM>(UiText(item)));
}

void FillFormatCombo(HWND dialog) {
    for (const auto& option : kFormatOptions) {
        const LRESULT index = SendDlgItemMessageW(
            dialog, IDC_CMB_FORMAT, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(UiText(option.name)));
        if (index != CB_ERR && index != CB_ERRSPACE)
            SendDlgItemMessageW(dialog, IDC_CMB_FORMAT, CB_SETITEMDATA,
                                index, option.value);
    }
}

unsigned char SelectedFormat(HWND dialog) {
    const LRESULT selection = SendDlgItemMessageW(
        dialog, IDC_CMB_FORMAT, CB_GETCURSEL, 0, 0);
    if (selection == CB_ERR) return kFormatAny;
    const LRESULT value = SendDlgItemMessageW(
        dialog, IDC_CMB_FORMAT, CB_GETITEMDATA, selection, 0);
    return value == CB_ERR ? kFormatAny : static_cast<unsigned char>(value);
}

int FormatIndex(unsigned char value) {
    for (int index = 0; index < static_cast<int>(_countof(kFormatOptions));
         ++index) {
        if (kFormatOptions[index].value == value) return index;
    }
    return 0;
}

const wchar_t* FormatName(unsigned char value) {
    return UiText(kFormatOptions[FormatIndex(value)].name);
}

bool ReadControlText(HWND dialog, int id, size_t limit, std::wstring& value) {
    HWND control = GetDlgItem(dialog, id);
    if (!control || limit > 32768) return false;
    std::wstring buffer(limit + 2, L'\0');
    const int length = GetWindowTextW(control, buffer.data(),
                                      static_cast<int>(buffer.size()));
    if (length < 0 || static_cast<size_t>(length) > limit) return false;
    buffer.resize(static_cast<size_t>(length));
    value = std::move(buffer);
    return true;
}

void Trim(std::wstring& value) {
    const size_t first = value.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) {
        value.clear();
        return;
    }
    const size_t last = value.find_last_not_of(L" \t\r\n");
    value = value.substr(first, last - first + 1);
}

int OperationIndex(unsigned char operations) {
    if (operations == kRuleRead) return 1;
    if (operations == kRuleWrite) return 2;
    return 0;
}

unsigned char OperationFromIndex(int index) {
    if (index == 1) return kRuleRead;
    if (index == 2) return kRuleWrite;
    return kRuleReadWrite;
}

int DecisionIndex(int action) {
    if (action == kRuleBlock) return 1;
    if (action == kRuleConfirm) return 2;
    return 0;
}

int DecisionFromIndex(int index) {
    if (index == 1) return kRuleBlock;
    if (index == 2) return kRuleConfirm;
    return kRuleAllow;
}

void UpdateEditState(HWND dialog) {
    const int sourceMode = static_cast<int>(SendDlgItemMessageW(
        dialog, IDC_CMB_SOURCE_MODE, CB_GETCURSEL, 0, 0));
    EnableWindow(GetDlgItem(dialog, IDC_ED_SOURCE_PATTERN),
                 sourceMode == kSourceName || sourceMode == kSourcePath);
    const int action = static_cast<int>(SendDlgItemMessageW(
        dialog, IDC_CMB_ACTION, CB_GETCURSEL, 0, 0));
    const BOOL confirmation = DecisionFromIndex(action) == kRuleConfirm;
    EnableWindow(GetDlgItem(dialog, IDC_ED_CONFIRM_TIMEOUT), confirmation);
    EnableWindow(GetDlgItem(dialog, IDC_CMB_TIMEOUT_ACTION), confirmation);
    const bool contentAvailable = SelectedFormat(dialog) != kFormatNonText;
    EnableWindow(GetDlgItem(dialog, IDC_ED_CONTENT_REGEX), contentAvailable);
    EnableWindow(GetDlgItem(dialog, IDC_CHK_REGEX_IGNORECASE),
                 contentAvailable);
    EnableWindow(GetDlgItem(dialog, IDC_ED_REGEX_SAMPLE), contentAvailable);
    EnableWindow(GetDlgItem(dialog, IDC_BTN_TEST_REGEX), contentAvailable);
    EnableWindow(GetDlgItem(dialog, IDC_LBL_REGEX_RESULT), contentAvailable);
    if (!contentAvailable)
        SetDlgItemTextW(dialog, IDC_LBL_REGEX_RESULT, UiText(TextId::NA));
}

void TestRegex(HWND dialog) {
    std::wstring pattern;
    std::wstring sample;
    if (!ReadControlText(dialog, IDC_ED_CONTENT_REGEX,
                         kMaxContentRegexLength, pattern) ||
        !ReadControlText(dialog, IDC_ED_REGEX_SAMPLE,
                         kMaxRegexContentLength, sample)) {
        SetDlgItemTextW(dialog, IDC_LBL_REGEX_RESULT, UiText(TextId::TooLong));
        return;
    }
    const bool ignoreCase =
        IsDlgButtonChecked(dialog, IDC_CHK_REGEX_IGNORECASE) == BST_CHECKED;
    if (!IsContentRegexSupported(pattern, ignoreCase)) {
        SetDlgItemTextW(dialog, IDC_LBL_REGEX_RESULT, UiText(TextId::InvalidRegex));
        return;
    }
    const unsigned char format = SelectedFormat(dialog);
    if ((format == kFormatCryptoAddress ||
         format == kFormatPrivateKeyMnemonic) &&
        !RuleSemanticFormatMatches(format, sample)) {
        SetDlgItemTextW(dialog, IDC_LBL_REGEX_RESULT, UiText(TextId::WrongFormat));
        return;
    }
    if (pattern.empty()) {
        SetDlgItemTextW(dialog, IDC_LBL_REGEX_RESULT, UiText(TextId::Match));
        return;
    }
    SafeRegex expression;
    if (!expression.Compile(pattern, ignoreCase)) {
        SetDlgItemTextW(dialog, IDC_LBL_REGEX_RESULT, UiText(TextId::InvalidRegex));
        return;
    }
    SetDlgItemTextW(dialog, IDC_LBL_REGEX_RESULT,
                    expression.Search(sample) ? UiText(TextId::Match) : UiText(TextId::NoMatch));
}

INT_PTR CALLBACK EditRuleProc(HWND dialog, UINT message, WPARAM wParam,
                              LPARAM lParam) {
    static EditCtx* context = nullptr;
    switch (message) {
    case WM_INITDIALOG: {
        LocalizeDialog(dialog, IDD_RULE_EDIT);
        context = reinterpret_cast<EditCtx*>(lParam);
        FillCombo(dialog, IDC_CMB_TYPE, kTypeNames);
        FillCombo(dialog, IDC_CMB_ACTION, kDecisionNames);
        FillCombo(dialog, IDC_CMB_NOTIFICATION, kNotificationNames);
        FillCombo(dialog, IDC_CMB_OPERATION, kOperationNames);
        FillFormatCombo(dialog);
        FillCombo(dialog, IDC_CMB_SOURCE_MODE, kSourceNames);
        FillCombo(dialog, IDC_CMB_TIMEOUT_ACTION, kTimeoutNames);
        SendDlgItemMessageW(dialog, IDC_ED_RULE_NAME, EM_SETLIMITTEXT, 128, 0);
        SendDlgItemMessageW(dialog, IDC_ED_PATTERN, EM_SETLIMITTEXT, 32768, 0);
        SendDlgItemMessageW(dialog, IDC_ED_SOURCE_PATTERN, EM_SETLIMITTEXT,
                            32768, 0);
        SendDlgItemMessageW(dialog, IDC_ED_CONTENT_REGEX, EM_SETLIMITTEXT,
                            kMaxContentRegexLength, 0);
        SendDlgItemMessageW(dialog, IDC_ED_REGEX_SAMPLE, EM_SETLIMITTEXT,
                            kMaxRegexContentLength, 0);
        SendDlgItemMessageW(dialog, IDC_ED_CONFIRM_TIMEOUT, EM_SETLIMITTEXT, 2,
                            0);
        CheckDlgButton(dialog, IDC_CHK_RULE_ENABLED,
                       context->rule.enabled ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(dialog, IDC_CHK_REGEX_IGNORECASE,
                       context->rule.ignoreCase ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(dialog, IDC_CHK_HIDE_FROM_LOG_LIST,
                       context->rule.hideFromLogList ? BST_CHECKED
                                                    : BST_UNCHECKED);
        SetDlgItemTextW(dialog, IDC_ED_RULE_NAME, context->rule.name.c_str());
        SetDlgItemTextW(dialog, IDC_ED_PATTERN, context->rule.pattern.c_str());
        SetDlgItemTextW(dialog, IDC_ED_SOURCE_PATTERN,
                        context->rule.sourcePattern.c_str());
        SetDlgItemTextW(dialog, IDC_ED_CONTENT_REGEX,
                        context->rule.contentRegex.c_str());
        SetDlgItemInt(dialog, IDC_ED_CONFIRM_TIMEOUT,
                      (std::clamp)(context->rule.confirmTimeoutMs, 1000u,
                                   60000u) /
                          1000u,
                      FALSE);
        SendDlgItemMessageW(dialog, IDC_CMB_TYPE, CB_SETCURSEL,
                            context->rule.isPath ? 1 : 0, 0);
        SendDlgItemMessageW(dialog, IDC_CMB_ACTION, CB_SETCURSEL,
                            DecisionIndex(context->rule.action), 0);
        SendDlgItemMessageW(dialog, IDC_CMB_NOTIFICATION, CB_SETCURSEL,
                            context->rule.showNotification ? 1 : 0, 0);
        SendDlgItemMessageW(dialog, IDC_CMB_OPERATION, CB_SETCURSEL,
                            OperationIndex(context->rule.operations), 0);
        SendDlgItemMessageW(dialog, IDC_CMB_FORMAT, CB_SETCURSEL,
                            FormatIndex(context->rule.format), 0);
        SendDlgItemMessageW(dialog, IDC_CMB_SOURCE_MODE, CB_SETCURSEL,
                            (std::min)(static_cast<int>(context->rule.sourceMode),
                                       static_cast<int>(kSourceUnknown)), 0);
        SendDlgItemMessageW(dialog, IDC_CMB_TIMEOUT_ACTION, CB_SETCURSEL,
                            context->rule.timeoutBlock ? 0 : 1, 0);
        UpdateEditState(dialog);
        return TRUE;
    }
    case WM_COMMAND: {
        const WORD id = LOWORD(wParam);
        const WORD notification = HIWORD(wParam);
        if ((id == IDC_CMB_SOURCE_MODE || id == IDC_CMB_ACTION) &&
            notification == CBN_SELCHANGE) {
            UpdateEditState(dialog);
            return TRUE;
        }
        if (id == IDC_CMB_FORMAT && notification == CBN_SELCHANGE) {
            UpdateEditState(dialog);
            if (SelectedFormat(dialog) != kFormatNonText)
                SetDlgItemTextW(dialog, IDC_LBL_REGEX_RESULT, UiText(TextId::NotTested));
            return TRUE;
        }
        if (id == IDC_BTN_TEST_REGEX) {
            TestRegex(dialog);
            return TRUE;
        }
        if (id == IDOK) {
            Rule candidate = context->rule;
            if (!ReadControlText(dialog, IDC_ED_RULE_NAME, 128,
                                 candidate.name) ||
                !ReadControlText(dialog, IDC_ED_PATTERN, 32768,
                                 candidate.pattern) ||
                !ReadControlText(dialog, IDC_ED_SOURCE_PATTERN, 32768,
                                 candidate.sourcePattern) ||
                !ReadControlText(dialog, IDC_ED_CONTENT_REGEX,
                                 kMaxContentRegexLength,
                                 candidate.contentRegex)) {
                UiMessageBox(dialog, UiText(TextId::ARuleFieldIsTooLongTo), UiText(TextId::InvalidRule),
                            MB_ICONWARNING);
                return TRUE;
            }
            Trim(candidate.name);
            Trim(candidate.pattern);
            Trim(candidate.sourcePattern);
            if (candidate.name.empty()) {
                UiMessageBox(dialog, UiText(TextId::EnterADescriptiveRuleName), UiText(TextId::InvalidRule),
                            MB_ICONWARNING);
                return TRUE;
            }
            if (candidate.pattern.empty()) {
                UiMessageBox(dialog, UiText(TextId::TheProcessConditionCannotBeEmptyUse),
                            UiText(TextId::InvalidRule), MB_ICONWARNING);
                return TRUE;
            }
            candidate.isPath = SendDlgItemMessageW(
                                   dialog, IDC_CMB_TYPE, CB_GETCURSEL, 0, 0) ==
                               1;
            candidate.action = DecisionFromIndex(static_cast<int>(
                SendDlgItemMessageW(dialog, IDC_CMB_ACTION, CB_GETCURSEL, 0,
                                    0)));
            candidate.showNotification = SendDlgItemMessageW(
                dialog, IDC_CMB_NOTIFICATION, CB_GETCURSEL, 0, 0) == 1;
            candidate.hideFromLogList =
                IsDlgButtonChecked(dialog, IDC_CHK_HIDE_FROM_LOG_LIST) ==
                BST_CHECKED;
            candidate.operations = OperationFromIndex(static_cast<int>(
                SendDlgItemMessageW(dialog, IDC_CMB_OPERATION, CB_GETCURSEL, 0,
                                    0)));
            candidate.format = SelectedFormat(dialog);
            if (candidate.format == kFormatNonText)
                candidate.contentRegex.clear();
            candidate.sourceMode = static_cast<unsigned char>(
                SendDlgItemMessageW(dialog, IDC_CMB_SOURCE_MODE, CB_GETCURSEL,
                                    0, 0));
            candidate.ignoreCase = IsDlgButtonChecked(
                                       dialog, IDC_CHK_REGEX_IGNORECASE) ==
                                   BST_CHECKED;
            candidate.enabled = IsDlgButtonChecked(
                                    dialog, IDC_CHK_RULE_ENABLED) == BST_CHECKED;
            candidate.timeoutBlock = SendDlgItemMessageW(
                                         dialog, IDC_CMB_TIMEOUT_ACTION,
                                         CB_GETCURSEL, 0, 0) == 0;
            BOOL timeoutValid = FALSE;
            const UINT timeoutSeconds = GetDlgItemInt(
                dialog, IDC_ED_CONFIRM_TIMEOUT, &timeoutValid, FALSE);
            if (candidate.action == kRuleConfirm &&
                (!timeoutValid || timeoutSeconds < 1 || timeoutSeconds > 60)) {
                UiMessageBox(dialog, UiText(TextId::TheConfirmationTimeoutMustBeBetween1),
                            UiText(TextId::InvalidRule), MB_ICONWARNING);
                return TRUE;
            }
            candidate.confirmTimeoutMs =
                (timeoutValid && timeoutSeconds >= 1 && timeoutSeconds <= 60)
                    ? timeoutSeconds * 1000u
                    : 15000u;
            if ((candidate.sourceMode == kSourceName ||
                 candidate.sourceMode == kSourcePath) &&
                candidate.sourcePattern.empty()) {
                UiMessageBox(dialog, UiText(TextId::EnterASourceProcessForTheSelected),
                            UiText(TextId::InvalidRule), MB_ICONWARNING);
                return TRUE;
            }
            if (!IsContentRegexSupported(candidate.contentRegex,
                                         candidate.ignoreCase)) {
                UiMessageBox(dialog,
                            UiText(TextId::TheContentRegexIsInvalidUnsupportedOr),
                            UiText(TextId::InvalidRule), MB_ICONWARNING);
                return TRUE;
            }
            std::vector<Rule> one{candidate};
            if (!IsRuleSetSupported(one)) {
                UiMessageBox(dialog, UiText(TextId::TheRuleFieldCombinationIsInvalid), UiText(TextId::InvalidRule),
                            MB_ICONWARNING);
                return TRUE;
            }
            context->rule = std::move(candidate);
            EndDialog(dialog, IDOK);
            return TRUE;
        }
        if (id == IDCANCEL) {
            EndDialog(dialog, IDCANCEL);
            return TRUE;
        }
        break;
    }
    }
    return FALSE;
}

bool EditRule(HWND owner, Rule& rule) {
    EditCtx context{rule};
    const INT_PTR result = DialogBoxParamW(
        g_app.hInst, MAKEINTRESOURCEW(IDD_RULE_EDIT), owner, EditRuleProc,
        reinterpret_cast<LPARAM>(&context));
    if (result != IDOK) return false;
    rule = std::move(context.rule);
    return true;
}

std::wstring SourceDescription(const Rule& rule) {
    if (rule.sourceMode == kSourceName || rule.sourceMode == kSourcePath)
        return std::wstring(UiText(kSourceNames[rule.sourceMode])) + UiText(TextId::Colon) +
               rule.sourcePattern;
    return UiText(kSourceNames[(std::min)(static_cast<int>(rule.sourceMode),
                                   static_cast<int>(kSourceUnknown))]);
}

void SetListText(HWND list, int row, int column, const std::wstring& value) {
    LVITEMW item = {};
    item.mask = LVIF_TEXT;
    item.iItem = row;
    item.iSubItem = column;
    item.pszText = const_cast<LPWSTR>(value.c_str());
    ListView_SetItem(list, &item);
}

void RefreshRuleList(HWND dialog, const std::vector<Rule>& rules,
                     int selected = -1) {
    HWND list = GetDlgItem(dialog, IDC_LIST_RULES);
    ListView_DeleteAllItems(list);
    for (size_t i = 0; i < rules.size(); ++i) {
        LVITEMW item = {};
        item.mask = LVIF_TEXT;
        item.iItem = static_cast<int>(i);
        std::wstring order = std::to_wstring(i + 1);
        item.pszText = order.data();
        const int row = ListView_InsertItem(list, &item);
        const Rule& rule = rules[i];
        SetListText(list, row, 1, rule.enabled ? UiText(TextId::Enabled) : UiText(TextId::Disabled));
        SetListText(list, row, 2,
                    rule.name.empty() ? std::wstring(UiText(TextId::Unnamed)) : rule.name);
        SetListText(list, row, 3,
                    std::wstring(UiText(rule.isPath ? kTypeNames[1] : kTypeNames[0])) +
                        UiText(TextId::Colon) + rule.pattern);
        SetListText(list, row, 4, SourceDescription(rule));
        SetListText(list, row, 5,
                    UiText(kOperationNames[OperationIndex(rule.operations)]));
        SetListText(list, row, 6, FormatName(rule.format));
        SetListText(list, row, 7,
                    rule.contentRegex.empty() ? std::wstring(UiText(TextId::AnyContent))
                                              : rule.contentRegex);
        SetListText(list, row, 8,
                    UiText(kDecisionNames[DecisionIndex(rule.action)]));
        std::wstring notification =
            UiText(kNotificationNames[rule.showNotification ? 1 : 0]);
        if (rule.hideFromLogList) notification += UiText(TextId::HiddenFromLog);
        SetListText(list, row, 9, notification);
    }
    if (selected >= 0 && selected < static_cast<int>(rules.size())) {
        ListView_SetItemState(list, selected, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(list, selected, FALSE);
    }
}

void InitRuleColumns(HWND dialog) {
    HWND list = GetDlgItem(dialog, IDC_LIST_RULES);
    ListView_SetExtendedListViewStyle(
        list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
    struct Column { const wchar_t* name; int width; };
    const Column columns[] = {
        {UiText(TextId::Order), 42}, {UiText(TextId::Status), 48}, {UiText(TextId::RuleName), 105},
        {UiText(TextId::Process), 145}, {UiText(TextId::Source), 150}, {UiText(TextId::Operation), 75},
        {UiText(TextId::Format2), 85}, {UiText(TextId::ContentCondition), 180}, {UiText(TextId::Decision), 75},
        {UiText(TextId::Notification), 95},
    };
    LVCOLUMNW column = {};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    column.fmt = LVCFMT_LEFT;
    for (int index = 0; index < static_cast<int>(_countof(columns)); ++index) {
        column.pszText = const_cast<LPWSTR>(columns[index].name);
        column.cx = columns[index].width;
        if (CurrentLanguage() == Language::English)
            column.cx = (std::max)(column.cx,
                ListView_GetStringWidth(list, column.pszText) + 24);
        ListView_InsertColumn(list, index, &column);
    }
}

int SelectedRule(HWND dialog) {
    return ListView_GetNextItem(GetDlgItem(dialog, IDC_LIST_RULES), -1,
                                LVNI_SELECTED);
}

void UpdateRuleButtons(HWND dialog, size_t count) {
    const int selected = SelectedRule(dialog);
    const BOOL valid = selected >= 0 && selected < static_cast<int>(count);
    EnableWindow(GetDlgItem(dialog, IDC_BTN_EDIT), valid);
    EnableWindow(GetDlgItem(dialog, IDC_BTN_DEL), valid);
    EnableWindow(GetDlgItem(dialog, IDC_BTN_UP), valid && selected > 0);
    EnableWindow(GetDlgItem(dialog, IDC_BTN_DOWN),
                 valid && selected + 1 < static_cast<int>(count));
}

INT_PTR CALLBACK RulesProc(HWND dialog, UINT message, WPARAM wParam,
                           LPARAM lParam) {
    static std::vector<Rule>* output = nullptr;
    static std::vector<Rule> work;
    static bool changed = false;
    switch (message) {
    case WM_INITDIALOG:
        LocalizeDialog(dialog, IDD_RULES);
        output = reinterpret_cast<std::vector<Rule>*>(lParam);
        work = *output;
        changed = false;
        InitRuleColumns(dialog);
        RefreshRuleList(dialog, work);
        UpdateRuleButtons(dialog, work.size());
        return TRUE;
    case WM_NOTIFY: {
        const auto* header = reinterpret_cast<NMHDR*>(lParam);
        if (header->idFrom != IDC_LIST_RULES) break;
        if (header->code == LVN_ITEMCHANGED) {
            UpdateRuleButtons(dialog, work.size());
            return TRUE;
        }
        if (header->code == NM_DBLCLK) {
            const int selected = SelectedRule(dialog);
            if (selected >= 0 && selected < static_cast<int>(work.size())) {
                Rule rule = work[static_cast<size_t>(selected)];
                if (EditRule(dialog, rule)) {
                    work[static_cast<size_t>(selected)] = std::move(rule);
                    changed = true;
                    RefreshRuleList(dialog, work, selected);
                }
            }
            return TRUE;
        }
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_ADD: {
            Rule rule;
            rule.name = UiText(TextId::NewRule);
            rule.pattern = L"*";
            if (EditRule(dialog, rule)) {
                work.push_back(std::move(rule));
                changed = true;
                RefreshRuleList(dialog, work,
                                static_cast<int>(work.size()) - 1);
            }
            return TRUE;
        }
        case IDC_BTN_EDIT: {
            const int selected = SelectedRule(dialog);
            if (selected < 0 || selected >= static_cast<int>(work.size()))
                return TRUE;
            Rule rule = work[static_cast<size_t>(selected)];
            if (EditRule(dialog, rule)) {
                work[static_cast<size_t>(selected)] = std::move(rule);
                changed = true;
                RefreshRuleList(dialog, work, selected);
            }
            return TRUE;
        }
        case IDC_BTN_DEL: {
            const int selected = SelectedRule(dialog);
            if (selected < 0 || selected >= static_cast<int>(work.size()))
                return TRUE;
            if (UiMessageBox(dialog, UiText(TextId::DeleteTheSelectedRule), UiText(TextId::DeleteRule),
                            MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES)
                return TRUE;
            work.erase(work.begin() + selected);
            changed = true;
            RefreshRuleList(dialog, work,
                            (std::min)(selected,
                                       static_cast<int>(work.size()) - 1));
            UpdateRuleButtons(dialog, work.size());
            return TRUE;
        }
        case IDC_BTN_UP:
        case IDC_BTN_DOWN: {
            const int selected = SelectedRule(dialog);
            const int next = LOWORD(wParam) == IDC_BTN_UP ? selected - 1
                                                          : selected + 1;
            if (selected < 0 || next < 0 ||
                next >= static_cast<int>(work.size()))
                return TRUE;
            std::swap(work[static_cast<size_t>(selected)],
                      work[static_cast<size_t>(next)]);
            changed = true;
            RefreshRuleList(dialog, work, next);
            return TRUE;
        }
        case IDOK:
            if (changed && !IsRuleSetSupported(work)) {
                UiMessageBox(dialog,
                            UiText(TextId::TheRuleCountFieldLengthRegexOr),
                            UiText(TextId::InvalidRule), MB_ICONWARNING);
                return TRUE;
            }
            if (changed) *output = work;
            EndDialog(dialog, changed ? IDOK : IDCANCEL);
            return TRUE;
        case IDCANCEL:
            EndDialog(dialog, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

} // namespace

bool ShowRulesDialog(HWND owner, std::vector<Rule>& rules) {
    std::vector<Rule> working = rules;
    const INT_PTR result = DialogBoxParamW(
        g_app.hInst, MAKEINTRESOURCEW(IDD_RULES), owner, RulesProc,
        reinterpret_cast<LPARAM>(&working));
    if (result != IDOK) return false;
    rules = std::move(working);
    return true;
}

bool ShowRuleEditor(HWND owner, Rule& rule) {
    return EditRule(owner, rule);
}

} // namespace clip
