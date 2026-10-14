#include "../../sub/SubscriptionDownloader.hpp"
#include <QCoreApplication>
#include <QUuid>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    NekoGui_sub::SubscriptionDownload result;
    result.source = "prior";
    QString error;
    const auto id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const NekoGui_sub::ManagedSubscriptionRequest request{QUrl("http://127.0.0.1:1/test"), "MDMBOX/0.1.0 mihomo/1.19.32"};
    if (NekoGui_sub::SubscriptionDownloader::fetch(request, id, result, error) ||
        error != "Invalid managed subscription download request" || result.source != "prior") return 1;
    return 0;
}
