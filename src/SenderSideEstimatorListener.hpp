#ifndef SENDERSIDEESTIMATORLISTENER_H
#define SENDERSIDEESTIMATORLISTENER_H

namespace py = pybind11;

class SenderSideEstimatorListener :
        public RemoteRateEstimator::Listener {
public:
    SenderSideEstimatorListener(py::function on_target_bitrate) {
        this->on_target_bitrate = on_target_bitrate;
    }

    virtual void onTargetBitrateRequested(uint32_t bitrate, uint32_t bandwidthEstimation, uint32_t totalBitrate) {
        on_target_bitrate(bitrate, bandwidthEstimation, totalBitrate);
    }

private:
    py::function on_target_bitrate;
};

#endif //SENDERSIDEESTIMATORLISTENER_H
