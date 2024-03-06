#ifndef ACTIVESPEAKERMULTIPLEXERFACADE_H
#define ACTIVESPEAKERMULTIPLEXERFACADE_H
#include <ActiveSpeakerMultiplexer.h>

namespace py = pybind11;

class ActiveSpeakerMultiplexerFacade :
        public ActiveSpeakerMultiplexer,
        public ActiveSpeakerMultiplexer::Listener {
public:
    ActiveSpeakerMultiplexerFacade(TimeService &timeService, py::function on_active_speaker_changed,
                                   py::function on_active_speaker_removed) : ActiveSpeakerMultiplexer(
        timeService, this) {
        this->on_active_speaker_changed = on_active_speaker_changed;
        this->on_active_speaker_removed = on_active_speaker_removed;
    }

    void onActiveSpeakerChanged(uint32_t speakerId, uint32_t multiplexerId) override {
        UltraDebug("-ActiveSpeakerMultiplexerFacade::onActiveSpeakerChanged() [speakerId:%d,multiplexerId:%d]\n",
                   speakerId, multiplexerId);
        on_active_speaker_changed(speakerId, multiplexerId);
    }

    void onActiveSpeakerRemoved(uint32_t multiplexerId) override {
        UltraDebug("-ActiveSpeakerMultiplexerFacade::onActiveSpeakerRemoved() [multiplexerId:%d]\n", multiplexerId);
        on_active_speaker_removed(multiplexerId);
    }

private:
    py::function on_active_speaker_changed;
    py::function on_active_speaker_removed;
};

#endif //ACTIVESPEAKERMULTIPLEXERFACADE_H
