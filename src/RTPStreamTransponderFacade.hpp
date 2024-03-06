#ifndef RTPSTREAMTRANSPONDERFACADE_H
#define RTPSTREAMTRANSPONDERFACADE_H

#include "../media-server/include/rtp/RTPStreamTransponder.h"

namespace py = pybind11;

class RTPStreamTransponderFacade :
        public RTPStreamTransponder {
public:
    RTPStreamTransponderFacade(const RTPOutgoingSourceGroup::shared &outgoing, const RTPSender::shared &sender,
                               py::function on_remb) : RTPStreamTransponder(outgoing, sender) {
        this->on_remb = on_remb;
    }

    virtual ~RTPStreamTransponderFacade() = default;

    void onREMB(const RTPOutgoingSourceGroup *group,DWORD ssrc, DWORD bitrate) override {
        //Check we have not send an update too recently (1s)
        if (getTimeDiff(last) / 1000 < period)
            //Do nothing
            return;

        //Update it
        last = getTime();

        on_remb(bitrate);
    }

    void SetMinPeriod(DWORD period) { this->period = period; }

private:
    DWORD period = 1000;
    QWORD last = 0;
    py::function on_remb;
};

#endif //RTPSTREAMTRANSPONDERFACADE_H
