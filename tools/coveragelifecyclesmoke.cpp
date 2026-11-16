#include "app.h"
#include "coveragemonitor.h"
#include <windows.h>
#include <cstdio>
#include <memory>
#include <thread>

namespace clip { App g_app; }

int main() {
    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE resume = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE joining = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE destroyed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!entered || !resume || !joining || !destroyed) return 1;
    auto monitor = std::make_unique<clip::CoverageMonitor>();
    if (!monitor->StartBlockedForTest(entered, resume, joining)) return 2;
    if (WaitForSingleObject(entered, 3000) != WAIT_OBJECT_0) {
        SetEvent(resume);
        return 3;
    }
    // A worker deliberately ignores stop until its gate opens. A failed Pause
    // must retain ownership; the destructor must then wait before reclaiming this.
    const bool pauseFailed = !monitor->Pause() && monitor->running();
    std::thread destroyer([&] {
        monitor.reset();
        SetEvent(destroyed);
    });
    const bool reachedJoin = WaitForSingleObject(joining, 3000) == WAIT_OBJECT_0;
    const bool blocked = WaitForSingleObject(destroyed, 0) == WAIT_TIMEOUT;
    SetEvent(resume);
    const bool finished = WaitForSingleObject(destroyed, 3000) == WAIT_OBJECT_0;
    destroyer.join();
    CloseHandle(entered);
    CloseHandle(resume);
    CloseHandle(joining);
    CloseHandle(destroyed);
    if (!pauseFailed || !reachedJoin || !blocked || !finished) {
        std::fprintf(stderr, "coverage-lifecycle-smoke-failed pause=%d join=%d blocked=%d finished=%d\n",
                     pauseFailed, reachedJoin, blocked, finished);
        return 4;
    }
    std::puts("pause-failure-retains-worker=1 destructor-joins-worker=1");
    return 0;
}
