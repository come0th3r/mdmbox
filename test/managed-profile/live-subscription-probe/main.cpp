#include "../../../sub/InstallationIdentity.hpp"
#include "../../../sub/ManagedProfile.hpp"
#include "../../../sub/ManagedProfileStore.hpp"
#include "../../../sub/MihomoValidator.hpp"
#include "../../../sub/SubscriptionDownloader.hpp"
#include "../../../sub/SubscriptionService.hpp"

#include <QCoreApplication>
#include <QDateTime>
#include <QTemporaryDir>
#include <QTextStream>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QTextStream input(stdin);
    QTextStream output(stdout);
    QTextStream diagnostics(stderr);

    if (app.arguments().size() != 2) {
        diagnostics << "Usage: mdmbox_live_subscription_probe <absolute-pinned-mihomo-path>\n";
        return 2;
    }

    QString error;
    const auto executable = app.arguments().at(1);
    if (!NekoGui_sub::MihomoValidator::verifyExecutable(executable, error)) {
        diagnostics << "Pinned core preflight failed.\n";
        return 3;
    }

    // Read secrets only from stdin. Never echo URLs, response bodies, profile
    // fields, metadata, HWID, or transport diagnostics to stdout/stderr.
    const auto revokedUrl = QUrl(input.readLine().trimmed(), QUrl::StrictMode);
    const auto workingUrl = QUrl(input.readLine().trimmed(), QUrl::StrictMode);
    if (!revokedUrl.isValid() || !workingUrl.isValid() ||
        revokedUrl.scheme() != "https" || workingUrl.scheme() != "https" ||
        revokedUrl.host().isEmpty() || workingUrl.host().isEmpty() ||
        !revokedUrl.userInfo().isEmpty() || !workingUrl.userInfo().isEmpty() ||
        revokedUrl == workingUrl) {
        diagnostics << "Two distinct HTTPS subscription URLs are required on stdin.\n";
        return 4;
    }

    QTemporaryDir temporary;
    if (!temporary.isValid()) {
        diagnostics << "Isolated temporary data directory unavailable.\n";
        return 5;
    }
    QString installationId;
    if (!NekoGui_sub::InstallationIdentity::loadOrCreate(temporary.path(), installationId, error)) {
        diagnostics << "Temporary installation identity unavailable.\n";
        return 6;
    }
    NekoGui_sub::ManagedProfileStore store(temporary.path() + QStringLiteral("/profiles"));
    const NekoGui_sub::SubscriptionService::Fetcher fetch =
        [](const NekoGui_sub::ManagedSubscriptionRequest &request, const QString &identity,
           NekoGui_sub::SubscriptionDownload &download, QString &fetchError, const std::atomic_bool *cancel) {
            return NekoGui_sub::SubscriptionDownloader::fetch(request, identity, download, fetchError, cancel);
        };
    const NekoGui_sub::ManagedProfileStore::Validator validate =
        [&](const NekoGui_sub::ManagedProfile &profile, QString &validationError) {
            return NekoGui_sub::MihomoValidator::validate(executable, profile, validationError);
        };

    const auto probe = [&](const QUrl &url, int groupId, const char *label) {
        bool transportCompleted = false;
        bool bodyReceived = false;
        QByteArray responseSource;
        NekoGui_sub::SubscriptionMetadata responseMetadata;
        bool validatorCalled = false;
        bool validatorAccepted = false;
        NekoGui_sub::SubscriptionFetchDiagnostics fetchDiagnostics;
        const NekoGui_sub::SubscriptionService::Fetcher observedFetch =
            [&](const NekoGui_sub::ManagedSubscriptionRequest &request, const QString &identity,
                NekoGui_sub::SubscriptionDownload &download, QString &fetchError, const std::atomic_bool *cancel) {
                transportCompleted = NekoGui_sub::SubscriptionDownloader::fetch(
                    request, identity, download, fetchError, cancel, 15000, &fetchDiagnostics);
                bodyReceived = transportCompleted && !download.source.trimmed().isEmpty();
                if (transportCompleted) {
                    responseSource = download.source;
                    responseMetadata = download.metadata;
                }
                return transportCompleted;
            };
        const NekoGui_sub::ManagedProfileStore::Validator observedValidator =
            [&](const NekoGui_sub::ManagedProfile &profile, QString &validationError) {
                validatorCalled = true;
                validatorAccepted = validate(profile, validationError);
                return validatorAccepted;
            };
        NekoGui_sub::SubscriptionService::CommittedSnapshot committed;
        const auto succeeded = NekoGui_sub::SubscriptionService::refresh(
            groupId, url, QStringLiteral("4.0.1-2024-12-12"), temporary.path(),
            store, observedFetch, observedValidator, error, nullptr, &committed);

        QString result;
        if (succeeded && bodyReceived && !committed.profile.source.isEmpty()) {
            result = QStringLiteral("ACCEPTED_AND_CONFIG_VALIDATED");
        } else if (bodyReceived) {
            NekoGui_sub::ManagedProfile candidate;
            QString parseError;
            if (!NekoGui_sub::ManagedProfile::ParseMihomo(responseSource, candidate, parseError) &&
                parseError.contains(QStringLiteral("notice"), Qt::CaseInsensitive)) {
                result = QStringLiteral("DENIAL_OR_UNAVAILABLE_STUB_REJECTED");
            } else if (!parseError.isEmpty()) {
                result = QStringLiteral("INVALID_OR_UNSUPPORTED_PROFILE_REJECTED");
            } else if (responseMetadata.expired(QDateTime::currentSecsSinceEpoch()) ||
                       responseMetadata.exhausted()) {
                result = QStringLiteral("EXPIRED_OR_EXHAUSTED_METADATA_REJECTED");
            } else if (validatorCalled && !validatorAccepted) {
                result = QStringLiteral("PINNED_CORE_CONFIG_REJECTED");
            } else {
                result = QStringLiteral("STORE_OR_COMMIT_REJECTED");
            }
        } else if (!transportCompleted) {
            result = QStringLiteral("HTTPS_FETCH_REJECTED");
        } else {
            result = QStringLiteral("EMPTY_RESPONSE");
        }
        output << label << '=' << result
               << " http=" << fetchDiagnostics.httpStatus
               << " net=" << fetchDiagnostics.networkError
               << " tls=" << (fetchDiagnostics.tlsError ? 1 : 0)
               << " bytes=" << fetchDiagnostics.responseBytes << Qt::endl;
        return succeeded;
    };

    const bool workingAccepted = probe(workingUrl, 2, "working");
    const bool revokedAccepted = probe(revokedUrl, 1, "revoked");
    if (revokedAccepted || !workingAccepted) return 7;
    output << "LIVE_SUBSCRIPTION_REVOCATION_THEN_WORKING_CONTROL_PASS" << Qt::endl;
    return 0;
}
