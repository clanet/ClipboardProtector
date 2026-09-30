#pragma once
#include <windows.h>

namespace clip {

enum class AutostartState { Enabled, Disabled, Absent };

bool EnableAutostart();
bool DisableAutostart();
bool RemoveAutostart();
// Returns false only when schtasks could not be queried.  On success, state
// distinguishes an enabled, disabled, or missing task.
bool QueryAutostart(AutostartState& state);
// Compatibility wrapper used by the settings dialog: false disables while
// preserving the task, so deleting a task is an explicit operation.
bool SetAutostart(bool enabled);
// Apply a requested state using a previously completed query, avoiding a
// second potentially slow schtasks query on the UI thread.
bool SetAutostart(bool enabled, AutostartState currentState);

} // namespace clip
