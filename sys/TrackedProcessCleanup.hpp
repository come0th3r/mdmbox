#pragma once

#include <QProcess>

namespace NekoGui_sys {
    // Must run on the tracked processes' owning thread. The stop callback is
    // bounded by its caller; do not discard a handle on an unconfirmed stop.
    template<typename Processes, typename Stop>
    bool cleanupTrackedProcesses(Processes &processes, const Stop &stop) {
        for (auto it = processes.begin(); it != processes.end();) {
            const auto process = *it;
            if (!process) { // Corrupt tracking is not proof of shutdown.
                ++it;
                continue;
            }
            stop(*process);
            if (process->state() == QProcess::NotRunning) it = processes.erase(it);
            else ++it;
        }
        return processes.empty();
    }
}
