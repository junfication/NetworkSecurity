#pragma once
#include <iostream>
#include "Database.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/rsa.h>
#include <chrono>
#include <random>
#include <fstream>

#pragma comment(lib, "Ws2_32.lib")

namespace TLSServer
{
  SOCKET createSocket(int port);
  void initSSL();
  void initWinsock(WSADATA* wsa);
  void shutDown(SOCKET s, SSL_CTX* ctx);
  SSL_CTX* createContext();
  void configContext(SSL_CTX* ctx);
  RSA* createRSA();
  std::string GenerateSessionKey();

  struct Session
  {
    SOCKET s;
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
    unsigned int it = 0;
    bool b = false;
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
  };
}