#pragma once

#include "SubscriptionContract.hpp"
#include <atomic>

namespace NekoGui_sub {
    struct SubscriptionDownload {
        QByteArray source;
        SubscriptionMetadata metadata;
    };

    class SubscriptionDownloader {
    public:
        // Synchronous worker-thread API. Failure leaves result untouched.
        static bool fetch(const ManagedSubscriptionRequest &request, const QString &installationId,
                          SubscriptionDownload &result, QString &error,
                          const std::atomic_bool *cancel = nullptr, int timeoutMs = 15000);
    };
}
