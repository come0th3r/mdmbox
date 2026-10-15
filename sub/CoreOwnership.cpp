#include "CoreOwnership.hpp"

namespace NekoGui_sub {
    CoreOwnership &CoreOwnership::shared() {
        static CoreOwnership instance;
        return instance;
    }

    bool CoreOwnership::acquire(Owner owner, QString &error) {
        error.clear();
        if (owner == Owner::None) { error = QStringLiteral("Cannot acquire an empty core owner"); return false; }
        QMutexLocker lock(&mutex);
        if (active != Owner::None) {
            error = current == State::Uncertain ? QStringLiteral("Core shutdown is unconfirmed; runtime ownership remains blocked")
                  : active == owner ? QStringLiteral("Core ownership is already held by this runtime")
                                    : QStringLiteral("Another core runtime already owns the network core");
            return false;
        }
        active = owner;
        current = State::Held;
        return true;
    }

    bool CoreOwnership::markUncertain(Owner owner, QString &error) {
        error.clear();
        QMutexLocker lock(&mutex);
        if (owner == Owner::None || active != owner) {
            error = QStringLiteral("Only the active runtime can mark ownership uncertain");
            return false;
        }
        current = State::Uncertain;
        return true;
    }

    bool CoreOwnership::release(Owner owner, QString &error) {
        error.clear();
        if (owner == Owner::None) { error = QStringLiteral("Cannot release an empty core owner"); return false; }
        QMutexLocker lock(&mutex);
        if (active != owner) {
            error = active == Owner::None ? QStringLiteral("Core ownership is not held")
                                          : QStringLiteral("Core ownership belongs to another runtime");
            return false;
        }
        active = Owner::None;
        current = State::Free;
        return true;
    }

    bool CoreOwnership::finishStop(Owner owner, bool stopped, QString &error) {
        error.clear();
        QMutexLocker lock(&mutex);
        if (owner == Owner::None || active != owner) {
            error = QStringLiteral("Stop result does not belong to the active runtime");
            return false;
        }
        if (!stopped || current == State::Uncertain) {
            current = State::Uncertain;
            error = QStringLiteral("Core shutdown is unconfirmed; restart the application");
            return false;
        }
        active = Owner::None;
        current = State::Free;
        return true;
    }

    CoreOwnership::Owner CoreOwnership::owner() const {
        QMutexLocker lock(&mutex);
        return active;
    }

    CoreOwnership::State CoreOwnership::state() const {
        QMutexLocker lock(&mutex);
        return current;
    }
}
