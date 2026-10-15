#include "../../sub/CoreOwnership.hpp"
#include <QCoreApplication>
#include <QTextStream>
#include <atomic>
#include <thread>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    using Ownership = NekoGui_sub::CoreOwnership;
    Ownership ownership;
    QString error;
    if (ownership.acquire(Ownership::Owner::None, error) || error.isEmpty()) return 1;
    if (!ownership.acquire(Ownership::Owner::Legacy, error) || ownership.owner() != Ownership::Owner::Legacy) return 2;
    if (ownership.acquire(Ownership::Owner::Managed, error) || error.isEmpty()) return 3;
    if (ownership.acquire(Ownership::Owner::Legacy, error) || error.isEmpty()) return 4;
    if (ownership.release(Ownership::Owner::Managed, error) || error.isEmpty()) return 5;
    if (!ownership.release(Ownership::Owner::Legacy, error) || ownership.owner() != Ownership::Owner::None) return 6;
    if (ownership.release(Ownership::Owner::Legacy, error) || error.isEmpty()) return 7;
    std::atomic<int> acquired{0};
    std::thread legacy([&] { QString e; if (ownership.acquire(Ownership::Owner::Legacy, e)) ++acquired; });
    std::thread managed([&] { QString e; if (ownership.acquire(Ownership::Owner::Managed, e)) ++acquired; });
    legacy.join(); managed.join();
    if (acquired != 1 || ownership.owner() == Ownership::Owner::None) return 8;
    const auto held = ownership.owner();
    if (!ownership.release(held, error) || ownership.owner() != Ownership::Owner::None) return 9;
    QTextStream(stdout) << "CORE_SINGLE_OWNER_ARBITRATION_PASS\n";
    return 0;
}
