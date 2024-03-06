#ifndef PLAYERFACADE_H
#define PLAYERFACADE_H

#include <mp4streamer.h>

namespace py = pybind11;

class PlayerFacade :
        public MP4Streamer,
        public MP4Streamer::Listener {
public:
    PlayerFacade(py::function on_end) : MP4Streamer(this),
                                        audio(new RTPIncomingSourceGroup(MediaFrame::Audio, loop)),
                                        video(new RTPIncomingSourceGroup(MediaFrame::Video, loop)) {
        this->on_end = on_end;
        Reset();
        //Start dispatching
        audio->Start();
        video->Start();
    }

    virtual void onRTPPacket(RTPPacket &packet) {
        //Get time
        auto now = getTimeMS();
        //Clone packet
        auto cloned = packet.Clone();
        //Copy payload
        cloned->AdquireMediaData();
        //Check media type
        switch (cloned->GetMediaType()) {
            case MediaFrame::Video:
                //Update stats
                video->media.Update(now, cloned->GetSeqNum(), cloned->GetMediaLength(),
                                    cloned->GetRTPHeader().GetSize());
            //Set ssrc of video
                cloned->SetSSRC(video->media.ssrc);
            //Multiplex
                video->AddPacket(cloned, 0, now);
                break;
            case MediaFrame::Audio:
                //Update stats
                audio->media.Update(now, cloned->GetSeqNum(), cloned->GetMediaLength(),
                                    cloned->GetRTPHeader().GetSize());
            //Set ssrc of audio
                cloned->SetSSRC(audio->media.ssrc);
            //Multiplex
                audio->AddPacket(cloned, 0, now);
                break;
            default:
                ///Ignore
                return;
        }
    }

    virtual void onTextFrame(TextFrame &frame) {
    }

    virtual void onEnd() {
        on_end();
    }

    void Reset() {
        audio->media.Reset();
        video->media.Reset();
        audio->media.ssrc = rand();
        video->media.ssrc = rand();
    }

    virtual void onMediaFrame(const MediaFrame &frame) {
    }

    virtual void onMediaFrame(DWORD ssrc, const MediaFrame &frame) {
    }

    RTPIncomingSourceGroup::shared GetAudioSource() { return audio; }
    RTPIncomingSourceGroup::shared GetVideoSource() { return video; }

private:
    py::function on_end;
    //TODO: Update to multitrack
    RTPIncomingSourceGroup::shared audio;
    RTPIncomingSourceGroup::shared video;
};

#endif //PLAYERFACADE_H
