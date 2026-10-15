#pragma once

#include <atomic>
#include <QtGlobal>
#include <limits>

namespace NekoGui_sys {
    // Accessed on the core thread and by queued GUI event consumers.
    class CoreProcessGeneration {
    public:
        bool advance() {
            auto value = serial.load();
            do {
                if (value == (std::numeric_limits<quint64>::max)()) return false;
            } while (!serial.compare_exchange_weak(value, value + 1));
            return true;
        }
        quint64 current() const { return serial.load(); }
        bool accepts(quint64 generation) const {
            return generation != 0 && generation == serial.load();
        }
    private:
        std::atomic<quint64> serial{0};
    };
}
