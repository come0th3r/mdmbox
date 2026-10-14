#pragma once

#include "ManagedProfileStore.hpp"
#include "SubscriptionDownloader.hpp"
#include <functional>

namespace NekoGui_sub {
    class SubscriptionService {
    public:
        using Fetcher = std::function<bool(const ManagedSubscriptionRequest &, const QString &,
                                          SubscriptionDownload &, QString &, const std::atomic_bool *)>;
        // Injected transport/validator permit deterministic tests; production binds pinned adapters.
        static bool refresh(int groupId, const QUrl &url, const QString &appVersion,
                            const QString &identityDirectory, ManagedProfileStore &store,
                            const Fetcher &fetch, const ManagedProfileStore::Validator &validate,
                            QString &error, const std::atomic_bool *cancel = nullptr);
    };
}
