#pragma once

#include <QMutex>
#include <QSemaphore>

namespace NekoGui_sys {
    // One callback producer, one waiting worker. Keep shared ownership in the
    // queued callback so a timeout cannot leave a dangling stack reference.
    class ProcessCleanupCompletion {
    public:
        void complete(bool stopped) {
            QMutexLocker lock(&mutex);
            if (state != State::Pending) return;
            state = stopped ? State::Stopped : State::Failed;
            completed.release();
        }

        bool wait(int timeoutMs) {
            // Invalid input must never turn QSemaphore's negative timeout into
            // an unbounded wait. A timeout is terminal, including late replies.
            const bool received = timeoutMs >= 0 && completed.tryAcquire(1, timeoutMs);
            QMutexLocker lock(&mutex);
            if (!received) state = State::TimedOut;
            return received && state == State::Stopped;
        }

    private:
        enum class State { Pending, Stopped, Failed, TimedOut };
        QMutex mutex;
        QSemaphore completed;
        State state = State::Pending;
    };
}
