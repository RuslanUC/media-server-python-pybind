from semanticsdp import SDPInfo, Setup, CandidateInfo, IceInfo, DTLSInfo

from pymedooze._pymedooze import DTLSICETransportListener, Properties, RTPBundleTransport
from pymedooze.utils import convert_rtp_properties, get_sdp_media


class Transport:
    def __init__(self, bundle: RTPBundleTransport, remote: SDPInfo, local: SDPInfo, *,
                 prefer_dtls_setup_active: bool = False, disable_stun_keepalive: bool = False,
                 srtp_protection_profiles: str = "", disable_remb: bool = False):
        self._bundle = bundle
        self._remote = remote
        self._local = local

        candidates, remote.candidates = remote.candidates, []

        properties = Properties()
        properties.set_string("ice.localUsername", local.ice.ufrag)
        properties.set_string("ice.localPassword", local.ice.pwd)
        properties.set_string("ice.remoteUsername", remote.ice.ufrag)
        properties.set_string("ice.remotePassword", remote.ice.pwd)

        properties.set_string("dtls.hash", remote.dtls.hash)
        properties.set_string("dtls.fingerprint", remote.dtls.fingerprint)
        properties.set_string("strpProtectionProfiles", srtp_protection_profiles)
        properties.set_bool("disableSTUNKeepAlive", disable_stun_keepalive)
        if prefer_dtls_setup_active and remote.dtls.setup == Setup.ACTPASS:
            properties.set_string("dtls.setup", "passive")
        else:
            properties.set_string("dtls.setup", remote.dtls.setup.value)

        if disable_remb:
            properties.set_bool("remb.disabled", True)

        self._username = f"{local.ice.ufrag}:{remote.ice.ufrag}"
        self._dtls_state = "new"

        self._native_connection = bundle.add_ice_transport(self._username, properties)
        self._native_transport = self._native_connection.transport

        self._listener = DTLSICETransportListener(
            self.on_ice_timeout,
            self.on_dtls_state_changed,
            self.on_remote_ice_candidate_activated
        )
        self._native_transport.set_listener(self._listener)

        # TODO: add ontargetbitrate event listener, SenderSideEstimatorListener, incomingStreams, outgoingStreams,
        #  incomingStreamTracks, outgoingStreamTracks, lfsr

        self.add_remote_candidates(candidates)

        self._audio_rtx = False

    def on_ice_timeout(self) -> None:
        print("ice_timeout")

    def on_dtls_state_changed(self, state: int) -> None:
        print(f"dtls_state_changed: {state=}")

    def on_remote_ice_candidate_activated(self, ip: str, port: int, priority: int) -> None:
        print(f"remote_ice_candidate_activated: {ip=}, {port=}, {priority=}")

    def add_remote_candidates(self, candidates: list[CandidateInfo]) -> ...:
        for candidate in candidates:
            if candidate.transport.lower() != "udp":
                continue

            if candidate.type == "relay":
                ip = candidate.rel_addr
                port = candidate.rel_port
            else:
                ip = candidate.address
                port = candidate.port

            if not self._bundle.add_remote_candidate(self._username, ip, port):
                continue

            self._remote.candidates.append(candidate)

    def get_local_candidates(self) -> list[CandidateInfo]:
        return self._local.candidates

    def get_local_ice(self) -> IceInfo:
        return self._local.ice

    def get_local_dtls(self) -> DTLSInfo:
        return self._local.dtls

    def set_remote_properties(self, props: SDPInfo) -> None:
        if media := get_sdp_media(props, "audio"):
            for codec in media.codecs.values():
                if codec.rtx is not None:
                    self._audio_rtx = True
                    break

        self._native_transport.set_remote_properties(convert_rtp_properties(props))

    def set_local_properties(self, props: SDPInfo) -> None:
        self._native_transport.set_local_properties(convert_rtp_properties(props))
