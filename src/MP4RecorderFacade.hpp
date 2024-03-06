#ifndef MP4RECORDERFACADE_H
#define MP4RECORDERFACADE_H
#include <mp4recorder.h>

namespace py = pybind11;

class MP4RecorderFacade :
        public MP4Recorder,
        public MP4Recorder::Listener {
public:
    MP4RecorderFacade(py::function on_first_frame, py::function on_closed) : MP4Recorder(this) {
        this->on_first_frame = on_first_frame;
        this->on_closed = on_closed;
    }

    void onFirstFrame(uint64_t time) override {
        on_first_frame(time);
    }

    void onClosed() override {
        on_first_frame();
    }

private:
    py::function on_first_frame;
    py::function on_closed;
};


#endif //MP4RECORDERFACADE_H
