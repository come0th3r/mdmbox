#pragma once

#include <QMutex>
#include <QString>

namespace NekoGui_sub {
    class CoreOwnership {
    public:
        enum class Owner { None, Legacy, Managed };
        bool acquire(Owner owner, QString &error);
        bool release(Owner owner, QString &error);
        [[nodiscard]] Owner owner() const;
    private:
        mutable QMutex mutex;
        Owner active = Owner::None;
    };
}
