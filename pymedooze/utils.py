from semanticsdp import SDPInfo, MediaInfo

from pymedooze._pymedooze import Properties


def get_sdp_media(sdp: SDPInfo, media_type: str) -> MediaInfo | None:
    for media in sdp.medias:
        if media.type == media_type:
            return media


def _to_properties(media: MediaInfo, props: Properties) -> None:
    if not media:
        return

    props.set_int(f"{media.type}.codecs.length", len(media.codecs))
    props.set_int(f"{media.type}.ext.length", len(media.extensions))

    for idx, codec in enumerate(media.codecs.values()):
        item = f"{media.type}.codecs.{idx}"
        props.set_string(f"{item}.codec", str(codec.codec))
        props.set_int(f"{item}.pt", int(codec.type))
        if codec.rtx:
            props.set_int(f"{item}.rtx", int(codec.rtx))

    for idx, (ext_id, ext_uri) in enumerate(media.extensions.items()):
        props.set_int(f"{media.type}.ext.{idx}.id", int(ext_id))
        props.set_string(f"{media.type}.ext.{idx}.uri", str(ext_uri))


def convert_rtp_properties(sdp: SDPInfo) -> Properties:
    audio = get_sdp_media(sdp, "audio")
    video = get_sdp_media(sdp, "video")

    props = Properties()

    _to_properties(audio, props)
    _to_properties(video, props)

    return props
