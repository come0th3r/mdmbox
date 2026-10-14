#pragma once

#include "ManagedProfile.hpp"
#include <functional>

namespace NekoGui_sub {
    class ManagedProfileStore {
    public:
        using Validator = std::function<bool(const ManagedProfile &, QString &)>;
        explicit ManagedProfileStore(QString directory);
        bool load(int groupId, ManagedProfile &profile, QString &error) const;
        bool commit(int groupId, const QByteArray &source, const Validator &validate, QString &error);

    private:
        QString directory;
        QString path(int groupId) const;
    };
}
