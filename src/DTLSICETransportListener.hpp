#ifndef DTLSICETRANSPORTLISTENER_H
#define DTLSICETRANSPORTLISTENER_H

namespace py = pybind11;

class DTLSICETransportListener : public DTLSICETransport::Listener {
public:
    DTLSICETransportListener(py::function on_ice_timeout, py::function on_dtls_state_changed,
                             py::function on_remote_ice_candidate_activated) {
        this->on_ice_timeout = on_ice_timeout;
        this->on_dtls_state_changed = on_dtls_state_changed;
        this->on_remote_ice_candidate_activated = on_remote_ice_candidate_activated;
    }

    ~DTLSICETransportListener() override = default;

    void onRemoteICECandidateActivated(const std::string &ip, uint16_t port, uint32_t priority) override {
        on_remote_ice_candidate_activated(ip, port, priority);
    }

    void onDTLSStateChanged(const DTLSICETransport::DTLSState state) override {
        std::string stateStr;
        switch (state) {
            case DTLSICETransport::DTLSState::New: {
                stateStr = "new";
                break;
            }
            case DTLSICETransport::DTLSState::Connecting: {
                stateStr = "connecting";
                break;
            }
            case DTLSICETransport::DTLSState::Connected: {
                stateStr = "connected";
                break;
            }
            case DTLSICETransport::DTLSState::Closed: {
                stateStr = "closed";
                break;
            }
            case DTLSICETransport::DTLSState::Failed: {
                stateStr = "failed";
                break;
            }
        }

        if (stateStr.empty())
            return;
        on_dtls_state_changed(stateStr);
    }

    void onICETimeout() override {
        on_ice_timeout();
    }

private:
    py::function on_ice_timeout;
    py::function on_dtls_state_changed;
    py::function on_remote_ice_candidate_activated;
};

#endif //DTLSICETRANSPORTLISTENER_H
