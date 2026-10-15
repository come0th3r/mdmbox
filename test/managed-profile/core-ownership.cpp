#include "../../sub/CoreOwnership.hpp"
#include "../../sub/LegacyCoreLifecycle.hpp"
#include "../../sys/CoreProcessGeneration.hpp"
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
    for (const auto owner : {Ownership::Owner::Legacy, Ownership::Owner::Managed}) {
        const auto other = owner == Ownership::Owner::Legacy ? Ownership::Owner::Managed : Ownership::Owner::Legacy;
        if (ownership.state() != Ownership::State::Free || !ownership.acquire(owner, error) ||
            ownership.state() != Ownership::State::Held) return 10;
        if (ownership.markUncertain(other, error) || error.isEmpty() ||
            ownership.markUncertain(Ownership::Owner::None, error) ||
            ownership.state() != Ownership::State::Held) return 11;
        if (!ownership.markUncertain(owner, error) || !ownership.markUncertain(owner, error) ||
            ownership.state() != Ownership::State::Uncertain || ownership.owner() != owner) return 12;
        // A fault notification is not permission to run either runtime again.
        if (ownership.acquire(other, error) || error.isEmpty() || ownership.acquire(owner, error) ||
            ownership.release(other, error) || ownership.state() != Ownership::State::Uncertain) return 13;
        // Simulate a later independently confirmed shutdown by the same owner.
        if (!ownership.release(owner, error) || ownership.state() != Ownership::State::Free ||
            !ownership.acquire(other, error) || !ownership.release(other, error)) return 14;
    }
    if (ownership.markUncertain(Ownership::Owner::Legacy, error) || error.isEmpty() ||
        ownership.state() != Ownership::State::Free) return 15;
    QTextStream(stdout) << "CORE_UNCERTAIN_OUTCOME_TRANSITIONS_PASS\n";
    using NekoGui_sub::LegacyCoreLifecycle;
    for (const bool rpc : {false, true}) {
        for (const bool external : {false, true}) {
            Ownership fixture;
            if (!fixture.acquire(Ownership::Owner::Legacy, error)) return 16;
            const bool stopped = LegacyCoreLifecycle::finishStop(fixture, rpc, external, error);
            if (stopped != (rpc && external)) return 17;
            if (stopped) {
                if (fixture.state() != Ownership::State::Free || !error.isEmpty() ||
                    !fixture.acquire(Ownership::Owner::Managed, error)) return 18;
            } else {
                if (fixture.owner() != Ownership::Owner::Legacy || fixture.state() != Ownership::State::Uncertain ||
                    error.isEmpty() || fixture.acquire(Ownership::Owner::Managed, error)) return 19;
                // A later successful reply may belong to a restarted daemon.
                if (LegacyCoreLifecycle::finishStop(fixture, true, true, error) ||
                    fixture.state() != Ownership::State::Uncertain) return 20;
            }
        }
    }
    Ownership foreign;
    if (LegacyCoreLifecycle::finishStop(foreign, true, true, error) ||
        foreign.state() != Ownership::State::Free ||
        !foreign.acquire(Ownership::Owner::Managed, error) ||
        LegacyCoreLifecycle::finishStop(foreign, false, false, error) ||
        foreign.owner() != Ownership::Owner::Managed || foreign.state() != Ownership::State::Held) return 21;
    QTextStream(stdout) << "LEGACY_STOP_OUTCOME_MATRIX_PASS\n";
    // A stop reply and a crash notification must have one mutex-serialized
    // outcome: Free if stop won, or Legacy/Uncertain if the fault won first.
    for (int iteration = 0; iteration < 200; ++iteration) {
        Ownership concurrent;
        if (!concurrent.acquire(Ownership::Owner::Legacy, error)) return 22;
        std::atomic<int> ready{0};
        std::atomic<bool> go{false};
        bool finished = false;
        bool faulted = false;
        auto awaitStart = [&] {
            ++ready;
            while (!go.load()) std::this_thread::yield();
        };
        std::thread stop([&] {
            awaitStart();
            QString e;
            finished = LegacyCoreLifecycle::finishStop(concurrent, true, true, e);
        });
        std::thread fault([&] {
            awaitStart();
            QString e;
            faulted = concurrent.markUncertain(Ownership::Owner::Legacy, e);
        });
        while (ready.load() != 2) std::this_thread::yield();
        go = true;
        stop.join();
        fault.join();
        if (finished == faulted) return 23;
        if (finished && (concurrent.owner() != Ownership::Owner::None || concurrent.state() != Ownership::State::Free)) return 24;
        if (faulted && (concurrent.owner() != Ownership::Owner::Legacy || concurrent.state() != Ownership::State::Uncertain)) return 25;
    }
    QTextStream(stdout) << "CORE_ATOMIC_STOP_FAULT_RACE_PASS iterations=200\n";
    for (const auto owner : {Ownership::Owner::Legacy, Ownership::Owner::Managed}) {
        Ownership generations;
        quint64 oldGeneration = 0, newGeneration = 0;
        if (!generations.acquire(owner, error, &oldGeneration) || oldGeneration == 0 ||
            generations.generation(owner) != oldGeneration ||
            !generations.release(owner, error, oldGeneration) ||
            !generations.acquire(owner, error, &newGeneration) || newGeneration <= oldGeneration) return 26;
        if (generations.release(owner, error, oldGeneration) || error.isEmpty() ||
            generations.markUncertain(owner, error, oldGeneration) ||
            generations.finishStop(owner, true, error, oldGeneration) ||
            generations.finishStop(owner, false, error, oldGeneration) ||
            generations.state() != Ownership::State::Held || generations.generation(owner) != newGeneration) return 27;
        if (!generations.markUncertain(owner, error, newGeneration) ||
            generations.finishStop(owner, true, error, newGeneration) ||
            !generations.release(owner, error, newGeneration) || generations.generation(owner) != 0) return 28;
        quint64 rejected = 123;
        if (!generations.acquire(owner, error, &newGeneration) ||
            generations.acquire(owner, error, &rejected) || rejected != 0) return 29;
    }
    QTextStream(stdout) << "CORE_STALE_GENERATION_REFUSAL_PASS\n";
    NekoGui_sys::CoreProcessGeneration daemon;
    if (daemon.accepts(0) || daemon.current() != 0 || !daemon.advance()) return 30;
    const auto oldDaemon = daemon.current();
    if (!daemon.accepts(oldDaemon) || !daemon.advance() || daemon.accepts(oldDaemon) ||
        daemon.accepts(0) || !daemon.accepts(daemon.current())) return 31;
    Ownership eventOwnership;
    quint64 oldOwner = 0, currentOwner = 0;
    if (!eventOwnership.acquire(Ownership::Owner::Legacy, error, &oldOwner) ||
        !eventOwnership.release(Ownership::Owner::Legacy, error, oldOwner) ||
        !eventOwnership.acquire(Ownership::Owner::Legacy, error, &currentOwner) ||
        eventOwnership.markUncertain(Ownership::Owner::Legacy, error, oldOwner) ||
        eventOwnership.state() != Ownership::State::Held) return 32;
    QTextStream(stdout) << "DAEMON_STALE_EVENT_GENERATION_PASS\n";
    QTextStream(stdout) << "CORE_SINGLE_OWNER_ARBITRATION_PASS\n";
    return 0;
}
