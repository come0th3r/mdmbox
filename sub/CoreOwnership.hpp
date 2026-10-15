#pragma once

#include <QMutex>
#include <QString>

namespace NekoGui_sub {
    class CoreOwnership {
    public:
        enum class Owner { None, Legacy, Managed };
        enum class State { Free, Held, Uncertain };
        // Both production runtime paths must use this instance.
        static CoreOwnership &shared();
        bool acquire(Owner owner, QString &error);
        // No release on an ambiguous RPC/process outcome. Only the current
        // owner can mark uncertainty; repeated fault notifications are safe.
        bool markUncertain(Owner owner, QString &error);
        // Caller must have confirmed that the owner's runtime is stopped.
        bool release(Owner owner, QString &error);
        // Atomically evaluate a normal stop result. Unlike confirmed cleanup
        // release(), a successful reply cannot clear pre-existing uncertainty.
        bool finishStop(Owner owner, bool stopped, QString &error);
        [[nodiscard]] Owner owner() const;
        [[nodiscard]] State state() const;
    private:
        mutable QMutex mutex;
        Owner active = Owner::None;
        State current = State::Free;
    };
}
