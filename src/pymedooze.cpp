#include <DTLSICETransport.h>
#include <PCAPTransportEmulator.h>
#include <RTPBundleTransport.h>
#include <SimulcastMediaFrameListener.h>
#include <pybind11/pybind11.h>
#include <rtp/RTPIncomingMediaStreamDepacketizer.h>

#include "MediaServer.hpp"
#include "DTLSICETransportListener.hpp"
#include "RTPSessionFacade.hpp"
#include "ActiveSpeakerDetectorFacade.hpp"
#include "ActiveSpeakerMultiplexerFacade.hpp"
#include "MediaFrameReader.hpp"
#include "MP4RecorderFacade.hpp"
#include "PlayerFacade.hpp"
#include "RTPStreamTransponderFacade.hpp"
#include "SenderSideEstimatorListener.hpp"

namespace py = pybind11;

Logger Logger::instance;

PYBIND11_MODULE(_pymedooze, m) {
    py::class_<MediaServer>(m, "MediaServer")
            .def_static("initialize", &MediaServer::Initialize)
            .def_static("terminate", &MediaServer::Terminate)
            .def_static("enable_log", &MediaServer::EnableLog)
            .def_static("enable_debug", &MediaServer::EnableDebug)
            .def_static("enable_ultradebug", &MediaServer::EnableUltraDebug)
            .def_static("set_port_range", &MediaServer::SetPortRange)
            .def_static("set_certificate", &MediaServer::SetCertificate)
            .def_static("get_fingerprint", &MediaServer::GetFingerprint)
            .def_static("set_affinity", &MediaServer::SetAffinity)
            .def_static("set_thread_name", &MediaServer::SetThreadName);

    py::class_<Properties>(m, "Properties")
            .def("set_int", py::overload_cast<const char *, int>(&Properties::SetProperty))
            .def("set_string", py::overload_cast<const char *, const char *>(&Properties::SetProperty))
            .def("set_bool", [](Properties &p, const char *key, bool val) {
                return p.SetProperty(std::string(key), std::to_string(val));
            });

    py::class_<EventLoop>(m, "EventLoop")
            .def("start", [](EventLoop &ev) { ev.Start(); })
            .def("stop", &EventLoop::Stop);

    py::class_<DTLSICETransportListener>(m, "DTLSICETransportListener")
            .def(py::init<py::function, py::function, py::function>());

    py::class_<DTLSICETransport>(m, "DTLSICETransport")
            .def("set_listener", &DTLSICETransport::SetListener)
            .def("start", &DTLSICETransport::Start)
            .def("stop", &DTLSICETransport::Stop)
            .def("set_srtp_protection_profiles", &DTLSICETransport::SetSRTPProtectionProfiles)
            .def("set_remote_properties", &DTLSICETransport::SetRemoteProperties)
            .def("set_local_properties", &DTLSICETransport::SetLocalProperties)
            .def("dump", py::overload_cast<const char *, bool, bool, bool, bool>(&DTLSICETransport::Dump))
            .def("dump", py::overload_cast<UDPDumper *, bool, bool, bool, bool>(&DTLSICETransport::Dump))
            .def("stop_dump", &DTLSICETransport::StopDump)
            .def("dump_bwe_stats", &DTLSICETransport::DumpBWEStats)
            .def("stop_dump_bwe_stats", &DTLSICETransport::StopDumpBWEStats)
            .def("reset", py::overload_cast<>(&DTLSICETransport::Reset))
            .def("activate_remote_candidate", &DTLSICETransport::ActivateRemoteCandidate)
            .def("set_remote_crypto_dtls", &DTLSICETransport::SetRemoteCryptoDTLS)
            .def("set_local_stun_credentials", &DTLSICETransport::SetLocalSTUNCredentials)
            .def("set_remote_stun_credentials", &DTLSICETransport::SetRemoteSTUNCredentials)
            .def("add_outgoing_source_group", &DTLSICETransport::AddOutgoingSourceGroup)
            .def("remove_outgoing_source_group", &DTLSICETransport::RemoveOutgoingSourceGroup)
            .def("add_incoming_source_group", &DTLSICETransport::AddIncomingSourceGroup)
            .def("remove_incoming_source_group", &DTLSICETransport::RemoveIncomingSourceGroup)
            .def("set_bandwidth_probing", &DTLSICETransport::SetBandwidthProbing)
            .def("set_max_probing_bitrate", &DTLSICETransport::SetMaxProbingBitrate)
            .def("set_probing_bitrate_limit", &DTLSICETransport::SetProbingBitrateLimit)
            .def("enable_sender_side_estimation", &DTLSICETransport::EnableSenderSideEstimation)
            .def("set_sender_side_estimator_listener", &DTLSICETransport::SetSenderSideEstimatorListener)
            .def("get_available_outgoing_bitrate", &DTLSICETransport::GetAvailableOutgoingBitrate)
            .def("get_estimated_outgoing_bitrate", &DTLSICETransport::GetEstimatedOutgoingBitrate)
            .def("get_total_sent_bitrate", &DTLSICETransport::GetTotalSentBitrate)
            .def("set_remote_override_bwe", &DTLSICETransport::SetRemoteOverrideBWE)
            .def("set_remote_override_bitrate", &DTLSICETransport::SetRemoteOverrideBitrate)
            .def("get_remote_username", &DTLSICETransport::GetRemoteUsername)
            .def("get_remote_pwd", &DTLSICETransport::GetRemotePwd)
            .def("get_local_username", &DTLSICETransport::GetLocalUsername)
            .def("get_local_pwd", &DTLSICETransport::GetLocalPwd)
            .def("get_rtt", &DTLSICETransport::GetRTT)
            .def("get_time_service", &DTLSICETransport::GetTimeService);

    py::class_<RTPBundleTransport>(m, "RTPBundleTransport")
            .def(py::init<uint32_t>())
            .def("init", py::overload_cast<>(&RTPBundleTransport::Init))
            .def("init", py::overload_cast<int>(&RTPBundleTransport::Init))
            .def("add_ice_transport", &RTPBundleTransport::AddICETransport)
            .def("restart_ice_transport", &RTPBundleTransport::RestartICETransport)
            .def("remove_ice_transport", &RTPBundleTransport::RemoveICETransport)
            .def("end", &RTPBundleTransport::End)
            .def("get_local_port", &RTPBundleTransport::GetLocalPort)
            .def("add_remote_candidate", &RTPBundleTransport::AddRemoteCandidate)
            .def("set_candidate_raw_tx_data", &RTPBundleTransport::SetCandidateRawTxData)
            .def("set_raw_tx", &RTPBundleTransport::SetRawTx)
            .def("clear_raw_tx", &RTPBundleTransport::ClearRawTx)
            .def("set_affinity", &RTPBundleTransport::SetAffinity)
            .def("set_thread_name", &RTPBundleTransport::SetThreadName)
            .def("set_priority", &RTPBundleTransport::SetPriority)
            .def("set_ice_timeout", &RTPBundleTransport::SetIceTimeout)
            .def("get_time_service", &RTPBundleTransport::GetTimeService);

    py::class_<RTPBundleTransport::Connection>(m, "RTPBundleTransportConnection")
            .def_readonly("transport", &RTPBundleTransport::Connection::transport);

    py::class_<RTPIncomingMediaStream>(m, "RTPIncomingMediaStream")
            .def("get_media_ssrc", &RTPIncomingMediaStream::GetMediaSSRC)
            .def("get_time_service", &RTPIncomingMediaStream::GetTimeService)
            .def("mute", &RTPIncomingMediaStream::Mute);

    py::class_<RTPIncomingMediaStreamMultiplexer>(m, "RTPIncomingMediaStreamMultiplexer")
            .def(py::init<const std::shared_ptr<RTPIncomingMediaStream>, TimeService &>())
            .def("stop", &RTPIncomingMediaStreamMultiplexer::Stop);

    py::class_<RTPIncomingSource>(m, "RTPIncomingSource")
            .def_readwrite("num_frames", &RTPIncomingSource::numFrames)
            .def_readwrite("num_frames_delta", &RTPIncomingSource::numFramesDelta)
            .def_readwrite("lost_packets", &RTPIncomingSource::lostPackets)
            .def_readwrite("lost_packets_delta", &RTPIncomingSource::lostPacketsDelta)
            .def_readwrite("lost_packets_max_gap", &RTPIncomingSource::lostPacketsMaxGap)
            .def_readwrite("lost_packets_gap_count", &RTPIncomingSource::lostPacketsGapCount)
            .def_readwrite("drop_packets", &RTPIncomingSource::dropPackets)
            .def_readwrite("total_packets_since_last_sr", &RTPIncomingSource::totalPacketsSinceLastSR)
            .def_readwrite("total_bytes_since_last_sr", &RTPIncomingSource::totalBytesSinceLastSR)
            .def_readwrite("min_ext_seq_num_since_last_sr", &RTPIncomingSource::minExtSeqNumSinceLastSR)
            .def_readwrite("lost_packets_since_last_sr", &RTPIncomingSource::lostPacketsSinceLastSR)
            .def_readwrite("last_received_sender_ntp_timestamp", &RTPIncomingSource::lastReceivedSenderNTPTimestamp)
            .def_readwrite("last_received_sender_report", &RTPIncomingSource::lastReceivedSenderReport)
            .def_readwrite("last_report", &RTPIncomingSource::lastReport)
            .def_readwrite("total_plis", &RTPIncomingSource::totalPLIs)
            .def_readwrite("total_nacks", &RTPIncomingSource::totalNACKs)
            .def_readwrite("frame_delay", &RTPIncomingSource::frameDelay)
            .def_readwrite("frame_delay_max", &RTPIncomingSource::frameDelayMax)
            .def_readwrite("frame_capture_delay", &RTPIncomingSource::frameCaptureDelay)
            .def_readwrite("frame_capture_delay_max", &RTPIncomingSource::frameCaptureDelayMax)
            .def_readwrite("skew", &RTPIncomingSource::skew)
            .def_readwrite("drift", &RTPIncomingSource::drift)
            .def_readwrite("aggregated_layers", &RTPIncomingSource::aggregatedLayers)
            .def_readwrite("width", &RTPIncomingSource::width)
            .def_readwrite("height", &RTPIncomingSource::height)
            .def("get_target_bitrate", [](RTPIncomingSource &self) { return self.targetBitrate.value_or(0); })
            .def("get_target_width", [](RTPIncomingSource &self) { return self.targetWidth.value_or(0); })
            .def("get_target_height", [](RTPIncomingSource &self) { return self.targetHeight.value_or(0); })
            .def("get_target_fps", [](RTPIncomingSource &self) { return self.targetFps.value_or(0); });

    py::class_<RTPOutgoingSource>(m, "RTPOutgoingSource")
            .def_readwrite("time", &RTPOutgoingSource::time)
            .def_readwrite("num_frames", &RTPOutgoingSource::numFrames)
            .def_readwrite("num_frames_delta", &RTPOutgoingSource::numFramesDelta)
            .def_readwrite("last_timestamp", &RTPOutgoingSource::lastTimestamp)
            .def_readwrite("last_sender_report", &RTPOutgoingSource::lastSenderReport)
            .def_readwrite("last_sender_report_ntp", &RTPOutgoingSource::lastSenderReportNTP)
            .def_readwrite("remb", &RTPOutgoingSource::remb)
            .def_readwrite("report_count", &RTPOutgoingSource::reportCount)
            .def_readwrite("report_count_delta", &RTPOutgoingSource::reportCountDelta)
            .def_readwrite("reported_lost_count", &RTPOutgoingSource::reportedLostCount)
            .def_readwrite("reported_lost_count_delta", &RTPOutgoingSource::reportedLostCountDelta)
            .def_readwrite("reported_fraction_lost", &RTPOutgoingSource::reportedFractionLost)
            .def_readwrite("reported_jitter", &RTPOutgoingSource::reportedJitter)
            .def_readwrite("rtt", &RTPOutgoingSource::rtt);

    py::class_<RTPIncomingSourceGroup>(m, "RTPIncomingSourceGroup")
            .def(py::init<MediaFrame::Type, TimeService &>())
            .def_readwrite("rid", &RTPIncomingSourceGroup::rid)
            .def_readwrite("mid", &RTPIncomingSourceGroup::mid)
            .def_readwrite("rtt", &RTPIncomingSourceGroup::rtt)
            .def_readwrite("type", &RTPIncomingSourceGroup::type)
            .def_readonly("media", &RTPIncomingSourceGroup::media)
            .def_readonly("rtx", &RTPIncomingSourceGroup::rtx)
            .def_readwrite("lost", &RTPIncomingSourceGroup::lost)
            .def_readwrite("min_waited_time", &RTPIncomingSourceGroup::minWaitedTime)
            .def_readwrite("max_waited_time", &RTPIncomingSourceGroup::maxWaitedTime)
            .def_readwrite("avg_waited_time", &RTPIncomingSourceGroup::avgWaitedTime)
            .def_readwrite("last_updated", &RTPIncomingSourceGroup::lastUpdated)
            .def("set_max_wait_time", &RTPIncomingSourceGroup::SetMaxWaitTime)
            .def("reset_max_wait_time", &RTPIncomingSourceGroup::ResetMaxWaitTime)
            .def("update", &RTPIncomingSourceGroup::Update)
            .def("stop", &RTPIncomingSourceGroup::Stop);

    py::class_<RTPOutgoingSourceGroup>(m, "RTPOutgoingSourceGroup")
            .def(py::init<MediaFrame::Type, TimeService &>())
            .def(py::init<const std::string &, MediaFrame::Type, TimeService &>())
            .def_readwrite("type", &RTPOutgoingSourceGroup::type)
            .def_readwrite("media", &RTPOutgoingSourceGroup::media)
            .def_readwrite("fec", &RTPOutgoingSourceGroup::fec)
            .def_readwrite("rtx", &RTPOutgoingSourceGroup::rtx)
            .def_readwrite("last_updated", &RTPOutgoingSourceGroup::lastUpdated)
            .def("set_forced_playout_delay", &RTPOutgoingSourceGroup::SetForcedPlayoutDelay)
            .def("update", py::overload_cast<>(&RTPOutgoingSourceGroup::Update))
            .def("stop", &RTPOutgoingSourceGroup::Stop);

    py::class_<RTPReceiver>(m, "RTPReceiver")
            .def("send_pli", &RTPReceiver::SendPLI)
            .def("reset", &RTPReceiver::Reset);

    py::class_<MediaFrame::Producer>(m, "MediaFrameProducer")
            .def("add_media_listener", &MediaFrame::Producer::AddMediaListener)
            .def("remove_media_listener", &MediaFrame::Producer::RemoveMediaListener);

    py::class_<LayerInfo>(m, "LayerInfo")
            .def_readwrite_static("max_layer_id", &LayerInfo::MaxLayerId)
            .def_readwrite("temporal_layer_id", &LayerInfo::temporalLayerId)
            .def_readwrite("spatial_layer_id", &LayerInfo::spatialLayerId);

    py::class_<LayerSource>(m, "LayerSource")
            .def_readwrite("num_packets", &LayerSource::numPackets)
            .def_readwrite("total_bytes", &LayerSource::totalBytes)
            .def_readwrite("bitrate", &LayerSource::bitrate)
            .def_readwrite("total_bitrate", &LayerSource::totalBitrate)
            .def_readwrite("active", &LayerSource::active)
            .def("get_target_bitrate", [](LayerSource &self) { return self.targetBitrate.value_or(0); })
            .def("get_target_width", [](LayerSource &self) { return self.targetWidth.value_or(0); })
            .def("get_target_height", [](LayerSource &self) { return self.targetHeight.value_or(0); })
            .def("get_target_fps", [](LayerSource &self) { return self.targetFps.value_or(0); });

    py::class_<RTPSource>(m, "RTPSource")
            .def_readwrite("ssrc", &RTPSource::ssrc)
            .def_readwrite("ext_seq_num", &RTPSource::extSeqNum)
            .def_readwrite("cycles", &RTPSource::cycles)
            .def_readwrite("jitter", &RTPSource::jitter)
            .def_readwrite("num_packets", &RTPSource::numPackets)
            .def_readwrite("num_packets_delta", &RTPSource::numPacketsDelta)
            .def_readwrite("num_rtcp_packets", &RTPSource::numRTCPPackets)
            .def_readwrite("total_bytes", &RTPSource::totalBytes)
            .def_readwrite("total_rtcp_bytes", &RTPSource::totalRTCPBytes)
            .def_readwrite("bitrate", &RTPSource::bitrate)
            .def_readwrite("total_bitrate", &RTPSource::totalBitrate)
            .def_readwrite("clockrate", &RTPSource::clockrate);

    py::class_<RTPSessionFacade>(m, "RTPSessionFacade")
            .def(py::init<MediaFrame::Type>())
            .def("init", &RTPSessionFacade::Init)
            .def("set_local_port", &RTPSessionFacade::SetLocalPort)
            .def("get_local_port", &RTPSessionFacade::GetLocalPort)
            .def("set_remote_port", &RTPSessionFacade::SetRemotePort)
            .def("get_outgoing_source_group", &RTPSessionFacade::GetOutgoingSourceGroup)
            .def("get_incoming_source_group", &RTPSessionFacade::GetIncomingSourceGroup)
            .def("end", &RTPSessionFacade::End)
            .def("send_pli", &RTPSessionFacade::SendPLI)
            .def("reset", &RTPSessionFacade::Reset)
            .def("get_time_service", &RTPSessionFacade::GetTimeService);

    py::class_<PCAPTransportEmulator>(m, "PCAPTransportEmulator")
            .def("set_remote_properties", &PCAPTransportEmulator::SetRemoteProperties)
            .def("add_incoming_source_group", &PCAPTransportEmulator::AddIncomingSourceGroup)
            .def("remove_incoming_source_group", &PCAPTransportEmulator::RemoveIncomingSourceGroup)
            .def("open", &PCAPTransportEmulator::Open)
            .def("set_reader", &PCAPTransportEmulator::SetReader)
            .def("play", &PCAPTransportEmulator::Play)
            .def("seek", &PCAPTransportEmulator::Seek)
            .def("stop", &PCAPTransportEmulator::Stop)
            .def("close", &PCAPTransportEmulator::Close)
            /*.def("get_time_service", &RTPSessionFacade::GetTimeService)*/;

    py::class_<ActiveSpeakerDetectorFacade>(m, "ActiveSpeakerDetector")
            .def(py::init<py::function>())
            .def("set_min_change_period", &ActiveSpeakerDetectorFacade::SetMinChangePeriod)
            .def("set_max_accumulated_score", &ActiveSpeakerDetectorFacade::SetMaxAccumulatedScore)
            .def("set_noise_gating_threshold", &ActiveSpeakerDetectorFacade::SetNoiseGatingThreshold)
            .def("set_min_activation_score", &ActiveSpeakerDetectorFacade::SetMinActivationScore)
            .def("add_incoming_source_group", &ActiveSpeakerDetectorFacade::AddIncomingSourceGroup)
            .def("remove_incoming_source_group", &ActiveSpeakerDetectorFacade::RemoveIncomingSourceGroup);

    py::class_<ActiveSpeakerMultiplexerFacade>(m, "ActiveSpeakerMultiplexerFacade")
            .def(py::init<TimeService &, py::function, py::function>())
            .def("set_max_accumulated_score", &ActiveSpeakerMultiplexerFacade::SetMaxAccumulatedScore)
            .def("set_noise_gating_threshold", &ActiveSpeakerMultiplexerFacade::SetNoiseGatingThreshold)
            .def("set_min_activation_score", &ActiveSpeakerMultiplexerFacade::SetMinActivationScore)
            .def("add_incoming_source_group", &ActiveSpeakerMultiplexerFacade::AddIncomingSourceGroup)
            .def("remove_incoming_source_group", &ActiveSpeakerMultiplexerFacade::RemoveIncomingSourceGroup)
            .def("add_rtp_stream_transponder", &ActiveSpeakerMultiplexerFacade::AddRTPStreamTransponder)
            .def("remove_rtp_stream_transponder", &ActiveSpeakerMultiplexerFacade::RemoveRTPStreamTransponder)
            .def("stop", &ActiveSpeakerMultiplexerFacade::Stop);

    py::class_<RTPIncomingMediaStreamDepacketizer>(m, "RTPIncomingMediaStreamDepacketizer")
            .def(py::init<std::shared_ptr<RTPIncomingMediaStream> &>())
            .def("stop", &RTPIncomingMediaStreamDepacketizer::Stop);

    /*py::class_<SimulcastMediaFrameListener>(m, "SimulcastMediaFrameListener")
            .def(py::init<TimeService &, DWORD, DWORD>())
            .def("set_num_layers", &SimulcastMediaFrameListener::SetNumLayers)
            .def("attach_to", &SimulcastMediaFrameListener::AttachTo)
            .def("detach", &SimulcastMediaFrameListener::Detach)
            .def("stop", &SimulcastMediaFrameListener::Stop)
            .def("add_media_listener", &SimulcastMediaFrameListener::AddMediaListener)
            .def("remove_media_listener", &SimulcastMediaFrameListener::RemoveMediaListener);*/

    py::class_<MediaFrameReader>(m, "MediaFrameReader")
            .def(py::init<py::function, bool, uint32_t, bool>())
            .def("grab_next_frame", &MediaFrameReader::GrabNextFrame);

    py::class_<MP4RecorderFacade>(m, "MP4RecorderFacade")
            .def(py::init<py::function, py::function>())
            .def("create", &MP4RecorderFacade::Create)
            .def("record", py::overload_cast<bool, bool>(&MP4RecorderFacade::Record))
            .def("stop", &MP4RecorderFacade::Stop)
            .def("close", py::overload_cast<>(&MP4RecorderFacade::Close))
            .def("set_time_shift_duration", &MP4RecorderFacade::SetTimeShiftDuration)
            .def("set_h_parameter_sets", &MP4RecorderFacade::SetH264ParameterSets)
            .def("close", py::overload_cast<bool>(&MP4RecorderFacade::Close));

    py::class_<PlayerFacade>(m, "PlayerFacade")
            .def(py::init<py::function>())
            .def("get_audio_source", &PlayerFacade::GetAudioSource)
            .def("get_video_source", &PlayerFacade::GetVideoSource)
            .def("reset", &PlayerFacade::Reset)
            .def("open", &PlayerFacade::Open)
            .def("has_audio_track", &PlayerFacade::HasAudioTrack)
            .def("has_video_track", &PlayerFacade::HasVideoTrack)
            .def("get_audio_codec", &PlayerFacade::GetAudioCodec)
            .def("get_video_codec", &PlayerFacade::GetVideoCodec)
            .def("get_duration", &PlayerFacade::GetDuration)
            .def("get_video_width", &PlayerFacade::GetVideoWidth)
            .def("get_video_height", &PlayerFacade::GetVideoHeight)
            .def("get_video_bitrate", &PlayerFacade::GetVideoBitrate)
            .def("get_video_framerate", &PlayerFacade::GetVideoFramerate)
            .def("play", &PlayerFacade::Play)
            .def("pre_seek", &PlayerFacade::PreSeek)
            .def("seek", &PlayerFacade::Seek)
            .def("tell", &PlayerFacade::Tell)
            .def("stop", &PlayerFacade::Stop)
            .def("close", &PlayerFacade::Close);

    py::class_<RTPStreamTransponderFacade>(m, "RTPStreamTransponderFacade")
            .def(py::init<std::shared_ptr<RTPOutgoingSourceGroup> &, std::shared_ptr<RTPSender> &, py::function>())
            .def("set_incoming", &RTPStreamTransponderFacade::SetIncoming)
            .def("reset_incoming", &RTPStreamTransponderFacade::ResetIncoming)
            .def("append_h_parameter_sets", &RTPStreamTransponderFacade::AppendH264ParameterSets)
            .def("select_layer", &RTPStreamTransponderFacade::SelectLayer)
            .def("mute", &RTPStreamTransponderFacade::Mute)
            .def("set_intra_only_forwarding", &RTPStreamTransponderFacade::SetIntraOnlyForwarding)
            .def("close", &RTPStreamTransponderFacade::Close);

    py::class_<SenderSideEstimatorListener>(m, "SenderSideEstimatorListener")
            .def(py::init<py::function>());

    py::class_<MediaFrame::Listener>(m, "MediaFrameListener");
    py::class_<RemoteRateEstimator::Listener>(m, "RemoteRateEstimatorListener");
}
