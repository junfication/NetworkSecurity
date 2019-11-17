#pragma once
#include <iostream>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/rsa.h>

#pragma comment(lib, "Ws2_32.lib")

namespace TLSClient
{
  void initSSL();
  SSL_CTX* createContext();
  void loadTrustStore(SSL_CTX* ctx);
  BIO* createConnection(SSL_CTX* ctx);
  void setConnection(std::string s, BIO* bio);
  SSL* setSSLMode(BIO* bio, SSL_CTX* ctx);
  void verifyConnection(SSL* ssl);
  void shutDown(BIO* bio, SSL* ssl, SSL_CTX* ctx);
  RSA* createRSA(SSL* ssl);
  
  struct CSession
  {
    SOCKET s;
    WSAData wsa;
    struct sockaddr_in server, client;
    unsigned char clientDataKey[32];
    unsigned char clientMacKey[32];
    unsigned char serverDataKey[32];
    unsigned char serverMacKey[32];
    unsigned short PortNum;
    unsigned char snonce[16];
    unsigned char cnonce[16];
    std::string fn;
    std::string data;
    bool b = false;
    int auth = 0;
    bool fin = false;
    char buf[2048];

    void InitSocket();
    void Send();
    void Recieve();
    void ShutDown();
    std::string Encrypt();
    void Decrypt(std::string msg);
    void Incrementsnonce();
    void Incrementcnonce();
    void Run();
    void Save();
  };

}