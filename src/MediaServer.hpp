#ifndef MEDIASERVER_HPP
#define MEDIASERVER_HPP

#include <dtls.h>
#include <OpenSSL.h>
#include <RTPTransport.h>

class MediaServer {
public:
    ~MediaServer() {
        Terminate();
    }

    static void Initialize() {
        Debug("-MediaServer::Initialize\n");
        //Initialize ssl
        OpenSSL::ClassInit();

        //Start DTLS
        DTLSConnection::Initialize();
    }

    static void Terminate() {
        Debug("-MediaServer::Terminate\n");
    }

    static void EnableLog(bool flag) {
        //Enable log
        Logger::EnableLog(flag);
    }

    static void EnableDebug(bool flag) {
        //Enable debug
        Logger::EnableDebug(flag);
    }

    static void EnableUltraDebug(bool flag) {
        //Enable debug
        Logger::EnableUltraDebug(flag);
    }

    static bool SetPortRange(int minPort, int maxPort) {
        return RTPTransport::SetPortRange(minPort, maxPort);
    }

    static bool SetCertificate(const char *cert, const char *key) {
        //Stop TLS
        DTLSConnection::Terminate();
        //Set new certificates
        DTLSConnection::SetCertificate(cert, key);
        //Start DTLS
        return DTLSConnection::Initialize();
    }

    static std::string GetFingerprint() {
        return DTLSConnection::GetCertificateFingerPrint(DTLSConnection::Hash::SHA256);
    }

    static bool SetAffinity(int cpu) {
        return EventLoop::SetAffinity(pthread_self(), cpu);
    }

    static bool SetThreadName(const std::string &name) {
        return EventLoop::SetThreadName(pthread_self(), name);
    }
};

#endif
