#include "CoreOwnership.hpp"
#include <limits>

namespace NekoGui_sub {
    CoreOwnership &CoreOwnership::shared() {
        static CoreOwnership instance;
        return instance;
    }

    bool CoreOwnership::acquire(Owner owner, QString &error, quint64 *generation) {
        error.clear();
        if (generation) *generation = 0;
        if (owner == Owner::None) { error = QStringLiteral("Cannot acquire an empty core owner"); return false; }
        QMutexLocker lock(&mutex);
        if (active != Owner::None) {
            error = current == State::Uncertain ? QStringLiteral("Core shutdown is unconfirmed; runtime ownership remains blocked")
                  : active == owner ? QStringLiteral("Core ownership is already held by this runtime")
                                    : QStringLiteral("Another core runtime already owns the network core");
            return false;
        }
        if (serial == (std::numeric_limits<quint64>::max)()) {
            error = QStringLiteral("Core ownership generation exhausted");
            return false;
        }
        ++serial;
        active = owner;
        current = State::Held;
        if (generation) *generation = serial;
        return true;
    }

    bool CoreOwnership::markUncertain(Owner owner, QString &error, quint64 generation) {
        error.clear();
        QMutexLocker lock(&mutex);
        if (generation != 0 && generation != serial) {
            error = QStringLiteral("Stale core ownership generation");
            return false;
        }
        if (owner == Owner::None || active != owner) {
            error = QStringLiteral("Only the active runtime can mark ownership uncertain");
            return false;
        }
        current = State::Uncertain;
        return true;
    }

    bool CoreOwnership::release(Owner owner, QString &error, quint64 generation) {
        error.clear();
        if (owner == Owner::None) { error = QStringLiteral("Cannot release an empty core owner"); return false; }
        QMutexLocker lock(&mutex);
        if (generation != 0 && generation != serial) {
            error = QStringLiteral("Stale core ownership generation");
            return false;
        }
        if (active != owner) {
            error = active == Owner::None ? QStringLiteral("Core ownership is not held")
                                          : QStringLiteral("Core ownership belongs to another runtime");
            return false;
        }
        active = Owner::None;
        current = State::Free;
        return true;
    }

    bool CoreOwnership::finishStop(Owner owner, bool stopped, QString &error, quint64 generation) {
        error.clear();
        QMutexLocker lock(&mutex);
        if (generation != 0 && generation != serial) {
            error = QStringLiteral("Stale core ownership generation");
            return false;
        }
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

    quint64 CoreOwnership::generation(Owner owner) const {
        QMutexLocker lock(&mutex);
        return owner != Owner::None && active == owner ? serial : 0;
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
