#pragma once

#include "SubscriptionContract.hpp"
#include <atomic>
#ifdef MDMBOX_TEST_TLS_CA_INJECTION
#include <QSslCertificate>
#endif

namespace NekoGui_sub {
    struct SubscriptionDownload {
        QByteArray source;
        SubscriptionMetadata metadata;
    };

    struct SubscriptionFetchDiagnostics {
        int httpStatus = 0;
        int networkError = 0;
        qint64 responseBytes = 0;
        bool tlsError = false;
    };

    class SubscriptionDownloader {
    public:
#ifdef MDMBOX_TEST_TLS_CA_INJECTION
        // Isolated-fixture trust only. The implementation restricts this to loopback hosts.
        static void setTestCaCertificates(const QList<QSslCertificate> &certificates);
        static void clearTestCaCertificates();
#endif
        // Synchronous worker-thread API. Failure leaves result untouched.
        static bool fetch(const ManagedSubscriptionRequest &request, const QString &installationId,
                          SubscriptionDownload &result, QString &error,
                          const std::atomic_bool *cancel = nullptr, int timeoutMs = 15000,
                          SubscriptionFetchDiagnostics *diagnostics = nullptr);
    };
}
