from __future__ import annotations

from semanticsdp import IceInfo, DTLSInfo, Setup, SDPInfo, CandidateInfo

from pymedooze._pymedooze import RTPBundleTransport, MediaServer
from pymedooze.transport import Transport


class Endpoint:
    def __init__(self, ip: str | list[str]):
        self._ips = ip if isinstance(ip, list) else [ip]
        self._bundle = RTPBundleTransport(0)
        if not self._bundle.init():
            raise RuntimeError("Could not initialize bundle for endpoint")

        self._fingerprint = MediaServer.get_fingerprint()
        self._candidates = []
        self._transports = set()

        for i in range(len(self._ips)):
            priority = (2 ** 24) * 126 + (2 ** 8) * (65535 - i) + 255
            self._candidates.append(CandidateInfo(
                "1", 1, "UDP", priority, self._ips[i], self._bundle.get_local_port(), "host"
            ))

    def get_local_port(self) -> int:
        return self._bundle.get_local_port()

    def get_dtls_fingerprint(self) -> str:
        return self._fingerprint

    def create_transport(self, remote: SDPInfo) -> Transport:
        local = SDPInfo(
            ice=IceInfo.generate(True),
            dtls=DTLSInfo(Setup.reverse(remote.dtls.setup, False), "sha-256", self.get_dtls_fingerprint()),
            candidates=self._candidates,
        )

        local.ice.lite = True
        local.ice.end_of_candidates = True

        transport = Transport(self._bundle, remote, local, disable_stun_keepalive=False, srtp_protection_profiles="")
        self._transports.add(transport)

        return transport
