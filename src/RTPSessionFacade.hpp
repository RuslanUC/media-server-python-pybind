#ifndef RTPSESSIONFACADE_H
#define RTPSESSIONFACADE_H
#include <rtpsession.h>

class RTPSessionFacade :
        public RTPSession,
        public RTPSender,
        public RTPReceiver {
public:
    RTPSessionFacade(MediaFrame::Type media) : RTPSession(media,NULL) {
        //Delegate to group
        delegate = true;
        //Start group dispatch
        GetIncomingSourceGroup()->Start();
    }

    virtual ~RTPSessionFacade() = default;

    virtual int Enqueue(const RTPPacket::shared &packet) { return SendPacket(packet); }
    virtual int SendPLI(DWORD ssrc) { return RequestFPU(); }
    virtual int Reset(DWORD ssrc) { return 1; }

    int Init(const Properties &properties) {
        RTPMap rtp;
        RTPMap apt;

        //Get codecs
        std::vector<Properties> codecs;
        properties.GetChildrenArray("codecs", codecs);

        //For each codec
        for (auto it = codecs.begin(); it != codecs.end(); ++it) {
            BYTE codec = (BYTE) -1;
            //Depending on the type
            switch (GetMediaType()) {
                case MediaFrame::Audio:
                    codec = (BYTE) AudioCodec::GetCodecForName(it->GetProperty("codec"));
                    break;
                case MediaFrame::Video:
                    codec = (BYTE) VideoCodec::GetCodecForName(it->GetProperty("codec"));
                    break;
                default:
                    //Skip
                    continue;
            }
            //If not found
            if (codec == (BYTE) -1)
                //Skip
                continue;
            //Get codec type
            BYTE type = it->GetProperty("pt", 0);
            //ADD it
            rtp.SetCodecForType(type, codec);
        }

        //Set local
        SetSendingRTPMap(rtp, apt);
        SetReceivingRTPMap(rtp, apt);

        //Set properties
        SetProperties(properties.GetChildren("properties"));

        //Call parent
        return RTPSession::Init();
    }
};

#endif //RTPSESSIONFACADE_H
