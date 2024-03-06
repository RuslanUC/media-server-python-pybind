#ifndef ACTIVESPEAKERDETECTORFACADE_H
#define ACTIVESPEAKERDETECTORFACADE_H
#include <ActiveSpeakerDetector.h>

namespace py = pybind11;

class ActiveSpeakerDetectorFacade :
        public ActiveSpeakerDetector,
        public ActiveSpeakerDetector::Listener,
        public RTPIncomingMediaStream::Listener {
public:
    ActiveSpeakerDetectorFacade(py::function on_active_speaker_changed) : ActiveSpeakerDetector(this) {
        this->on_active_speaker_changed = on_active_speaker_changed;
    };

    void onActiveSpeakerChanded(uint32_t id) override {
        UltraDebug("-ActiveSpeakerDetectorFacade::onActiveSpeakerChanded() [id:%d]\n", id);
        on_active_speaker_changed(id);
    }

    void AddIncomingSourceGroup(RTPIncomingMediaStream *incoming, uint32_t id) {
        Debug("-ActiveSpeakerDetectorFacade::AddIncomingSourceGroup() [incoming:%p,id:%d]\n", incoming, id);

        if (incoming) {
            ScopedLock lock(mutex);
            //Insert new
            auto [it,inserted] = sources.try_emplace(incoming, id);
            //If already present
            if (!inserted)
                //do nothing
                return;
            //Add us as rtp listeners
            incoming->AddListener(this);
            //initialize to silence
            ActiveSpeakerDetector::Accumulate(id, false, 127, getTimeMS());
        }
    }

    void RemoveIncomingSourceGroup(RTPIncomingMediaStream *incoming) {
        Debug("-ActiveSpeakerDetectorFacade::RemoveIncomingSourceGroup() [incoming:%p]\n", incoming);

        if (incoming) {
            ScopedLock lock(mutex);
            //Get map
            auto it = sources.find(incoming);
            //check it was present
            if (it == sources.end())
                //Do nothing, probably called onEnded before
                return;
            //Remove listener
            incoming->RemoveListener(this);
            //RElease id
            ActiveSpeakerDetector::Release(it->second);
            //Erase
            sources.erase(it);
        }
    }

    void onRTP(const RTPIncomingMediaStream *incoming, const RTPPacket::shared &packet) override {
        if (packet->HasAudioLevel()) {
            ScopedLock lock(mutex);
            //Get map
            auto it = sources.find(incoming);
            //check it was present
            if (it == sources.end())
                //Do nothing
                return;
            //Accumulate on id
            ActiveSpeakerDetector::Accumulate(it->second, packet->GetVAD(), packet->GetLevel(), getTimeMS());
        }
    }

    void onBye(const RTPIncomingMediaStream *group) override {
    }

    void onEnded(const RTPIncomingMediaStream *incoming) override {
        Debug("-ActiveSpeakerDetectorFacade::onEnded() [incoming:%p]\n", incoming);

        if (incoming) {
            ScopedLock lock(mutex);
            //Get map
            auto it = sources.find(incoming);
            //check it was present
            if (it == sources.end())
                //Do nothing
                return;
            //Release id
            ActiveSpeakerDetector::Release(it->second);
            //Erase
            sources.erase(it);
        }
    }

private:
    Mutex mutex;
    std::map<RTPIncomingMediaStream *, uint32_t, std::less<> > sources;
    py::function on_active_speaker_changed;
};

#endif //ACTIVESPEAKERDETECTORFACADE_H
