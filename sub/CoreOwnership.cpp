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
            error = active == owner ? QStringLiteral("Core ownership is already held by this runtime")
                                    : QStringLiteral("Another core runtime already owns the network core");
            return false;
        }
        active = owner;
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
        return true;
    }

    CoreOwnership::Owner CoreOwnership::owner() const {
        QMutexLocker lock(&mutex);
        return active;
    }
}
