#ifndef MEDIAFRAMEREADER_H
#define MEDIAFRAMEREADER_H

#include "codecs.h"

namespace py = pybind11;

class MediaFrameReader :
        public MediaFrame::Listener {
public:
    MediaFrameReader(py::function on_media_frame, bool intraOnly, uint32_t minPeriod, bool onDemand) {
        this->on_media_frame = on_media_frame;
        this->intraOnly = intraOnly;
        this->minPeriod = minPeriod;
        this->onDemand = onDemand;
    }

    virtual ~MediaFrameReader() = default;

    void onMediaFrame(const MediaFrame &frame) override {
        onMediaFrame(0, frame);
    }

    virtual void onMediaFrame(DWORD ssrc, const MediaFrame &frame) {
        //UltraDebug("-onMediaFrame() [minPeriod:%d,lastFrame:%lld]\n",minPeriod,lastFrame);

        if (intraOnly && frame.GetType() == MediaFrame::Video && !((VideoFrame *) &frame)->IsIntra())
            //Ignore non intra video frames
            return;

        //Get timestamp
        uint64_t now = getTimeMS();

        if (onDemand && !grabNextFrame)
            //Ignore non requested frames when on demand mode
            return;

        if (minPeriod && now < lastFrame + minPeriod)
            //Ignore frame before min perior
            return;

        //Update last frame time
        lastFrame = now;

        //Get media typ
        const char *type = MediaFrame::TypeToString(frame.GetType());
        const char *codec = frame.GetType() == MediaFrame::Video
                                ? VideoCodec::GetNameFor(((VideoFrame *) &frame)->GetCodec())
                                : AudioCodec::GetNameFor(((AudioFrame *) &frame)->GetCodec());
        //Got frame, reset flag
        grabNextFrame = false;

        //Get frame buffer
        Buffer::shared buffer = frame.GetBuffer();

        //UltraDebug("-onMediaFrame() [type:%s,codec:%s,minPeriod:%d,lastFrame:%d]\n",type,codec,minPeriod,lastFrame);
        py::bytes frameBytes(reinterpret_cast<const char *>(buffer->GetData()), buffer->GetSize());
        on_media_frame(frameBytes, type, codec);
    }

    void GrabNextFrame() {
        grabNextFrame = true;
    }

private:
    py::function on_media_frame;
    bool intraOnly = false;
    uint32_t minPeriod = 0;
    uint64_t lastFrame = 0;
    bool grabNextFrame = false;
    bool onDemand = false;
};

#endif //MEDIAFRAMEREADER_H
