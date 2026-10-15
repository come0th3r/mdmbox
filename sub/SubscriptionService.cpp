#include "SubscriptionService.hpp"
#include "InstallationIdentity.hpp"
#include <QDateTime>
#include <QDir>
#include <QLockFile>

namespace NekoGui_sub {
    bool SubscriptionService::refresh(int groupId, const QUrl &url, const QString &appVersion,
                                      const QString &identityDirectory, ManagedProfileStore &store,
                                      const Fetcher &fetch, const ManagedProfileStore::Validator &validate,
                                      QString &error, const std::atomic_bool *cancel, CommittedSnapshot *committed) {
        error.clear();
        if (groupId < 0 || !fetch || !validate) {
            error = QStringLiteral("Invalid managed subscription service dependencies");
            return false;
        }
        auto cancelled = [&] {
            if (!cancel || !cancel->load()) return false;
            error = QStringLiteral("Subscription refresh cancelled");
            return true;
        };
        if (cancelled()) return false;
        ManagedSubscriptionRequest request;
        // This service currently targets only the checksum-pinned v1.19.32 adapter.
        if (!ManagedSubscriptionRequest::build(url, appVersion, "1.19.32", request, error)) return false;
        QString identity;
        if (!InstallationIdentity::loadOrCreate(identityDirectory, identity, error)) return false;
        QLockFile refreshLock(QDir(identityDirectory).filePath(QStringLiteral("subscription-refresh-%1.lock").arg(groupId)));
        if (!refreshLock.tryLock(0)) {
            error = QStringLiteral("Subscription refresh already in progress");
            return false;
        }
        SubscriptionDownload download;
        if (!fetch(request, identity, download, error, cancel)) {
            error = QStringLiteral("Managed subscription download failed");
            return false;
        }
        if (cancelled()) return false;
        if (download.metadata.expired(QDateTime::currentSecsSinceEpoch()) || download.metadata.exhausted()) {
            error = QStringLiteral("Subscription is expired or exhausted");
            return false;
        }
        // Recheck cancellation after potentially slow validation, before disk commit.
        ManagedProfile validated;
        const auto guardedValidator = [&](const ManagedProfile &profile, QString &reason) {
            if (cancel && cancel->load()) return false;
            const bool accepted = validate(profile, reason);
            if (accepted) validated = profile;
            return accepted && !(cancel && cancel->load());
        };
        if (!store.commit(groupId, download.source, download.metadata, guardedValidator, error)) return false;
        // Return the exact validated commit, never reload a possibly newer envelope.
        // Preserve caller output on every failure, including failed disk writes.
        if (committed) *committed = CommittedSnapshot{validated, download.metadata};
        return true;
    }
}
