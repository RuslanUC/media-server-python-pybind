cmake_minimum_required(VERSION 3.20)
project(pymedooze)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)
fetchcontent_declare(
        mp4v2
        GIT_REPOSITORY https://github.com/medooze/mp4v2.git
        GIT_TAG master
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/mp4v2
)

FetchContent_MakeAvailable(mp4v2)

find_package(Python3 COMPONENTS Interpreter Development.Module REQUIRED)

find_path(AVCodec_INCLUDE_DIR
        NAMES libavcodec/avcodec.h ffmpeg/avcodec.h avcodec.h
        PATH_SUFFIXES ffmpeg
)

file(GLOB_RECURSE SOURCES_H265 RELATIVE ${CMAKE_CURRENT_LIST_DIR} "media-server/src/h265/*.cpp")
file(GLOB_RECURSE SOURCES_H264 RELATIVE ${CMAKE_CURRENT_LIST_DIR} "media-server/src/h264/*.cpp")
file(GLOB_RECURSE SOURCES_VP8 RELATIVE ${CMAKE_CURRENT_LIST_DIR} "media-server/src/vp8/*.cpp")
file(GLOB_RECURSE SOURCES_VP9 RELATIVE ${CMAKE_CURRENT_LIST_DIR} "media-server/src/vp9/*.cpp")
file(GLOB_RECURSE SOURCES_JPEG RELATIVE ${CMAKE_CURRENT_LIST_DIR} "media-server/src/jpeg/*.cpp")
file(GLOB_RECURSE SOURCES_WEBP RELATIVE ${CMAKE_CURRENT_LIST_DIR} "media-server/src/webp/*.cpp")
file(GLOB_RECURSE SOURCES_AAC RELATIVE ${CMAKE_CURRENT_LIST_DIR} "media-server/src/aac/*.cpp")
file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_CURRENT_LIST_DIR} "media-server/src/*.cpp")

add_library(pymedooze SHARED
        ${SOURCES_H264}
        ${SOURCES_H265}
        ${SOURCES_VP8}
        ${SOURCES_VP9}
        ${SOURCES_JPEG}
        ${SOURCES_WEBP}
        ${SOURCES_AAC}
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/crc32c/src/crc32c.cc
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/crc32c/src/crc32c_portable.cc
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/crc32c/src/crc32c_sse42.cc
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/crc32c/src/crc32c_arm64.cc
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/libdatachannels/src/Datachannels.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/MedoozeTracing.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/ActiveSpeakerDetector.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/ActiveSpeakerMultiplexer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/EventLoop.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/PacketHeader.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/MacAddress.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/RTPBundleTransport.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/DTLSICETransport.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/VideoLayerSelector.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/opus/opusdepacketizer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/h264/h264depacketizer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/h265/h265.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/h265/H265Depacketizer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/h265/HEVCDescriptor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/vp8/vp8depacketizer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/h264/H264LayerSelector.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/vp8/VP8LayerSelector.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/vp9/VP9PayloadDescription.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/vp9/VP9LayerSelector.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/vp9/VP9Depacketizer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/av1/AV1Depacketizer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/av1/AV1LayerSelector.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/av1/Obu.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/SRTPSession.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/dtls.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/CPUMonitor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/OpenSSL.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/RTPTransport.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/httpparser.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/stunmessage.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/crc32calc.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/http.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/avcdescriptor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/utf8.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/DependencyDescriptorLayerSelector.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/DependencyDescriptor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/LayerInfo.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPCommonHeader.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPHeader.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPHeaderExtension.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPApp.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPExtendedJitterReport.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPPacket.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPReport.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPSenderReport.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPMap.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPBye.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPFullIntraRequest.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPPayloadFeedback.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPRTPFeedback.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPDepacketizer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPPacket.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPPayload.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPCompoundPacket.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPNACK.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPReceiverReport.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTCPSDES.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPPacketSched.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPStreamTransponder.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPLostPackets.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPSource.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPIncomingMediaStreamMultiplexer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPIncomingMediaStreamDepacketizer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPIncomingSource.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPIncomingSourceGroup.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPOutgoingSource.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtp/RTPOutgoingSourceGroup.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/mp4recorder.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/mp4streamer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/rtpsession.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/RTPTransport.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/PCAPFile.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/PCAPReader.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/PCAPTransportEmulator.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/remoteratecontrol.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/remoterateestimator.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/SendSideBandwidthEstimation.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/SimulcastMediaFrameListener.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/ForwardErrorCorrection.cpp
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src/FecProbeGenerator.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/EventSource.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/pymedooze.cpp
)

target_include_directories(pymedooze PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src
        ${CMAKE_CURRENT_LIST_DIR}/src/include
        ${CMAKE_CURRENT_LIST_DIR}/media-server/include
        ${CMAKE_CURRENT_LIST_DIR}/media-server/src
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/libdatachannels/src
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/libdatachannels/src/internal
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/mp4v2/include
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/crc32c/include
        ${CMAKE_CURRENT_LIST_DIR}/media-server/ext/crc32c/config/Linux-x86_64
        ${Python3_INCLUDE_DIRS}
        ${AVCodec_INCLUDE_DIR}
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native -fexceptions -g -flto")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -fexceptions -std=c++17 -g -flto")
target_compile_options(mp4v2-static PUBLIC -Wno-narrowing -fPIC)
set_target_properties(pymedooze PROPERTIES PREFIX "" SUFFIX "${CMAKE_LIBRARY_SUFFIX}" OUTPUT_NAME "_pymedooze")
#target_link_options(pymedooze PUBLIC "-Wl,--no-undefined")

target_link_libraries(pymedooze
        pthread
        vpx
        x264
        avcodec
        avutil
        swscale
        swresample
        crypto
        mp4v2-static
        srtp2
        ssl
)
