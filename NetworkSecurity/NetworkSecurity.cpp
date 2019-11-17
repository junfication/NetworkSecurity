// NetworkSecurity.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include <iostream>
#include <fstream>
#include <map>
#include "TLSServer.h"
#include "TLSClient.h"
//#define SERVER_IS_ON 1
#define LENGTH 2048
#include <openssl/sha.h>
#include <openssl/rsa.h>

int main()
{
#if defined(SERVER_IS_ON)
  //server
  while (true)
  {
    Database db;
    db.Open();
    db.Load();
    WSAData wsa;
    TLSServer::initSSL();
    TLSServer::initWinsock(&wsa);
    SOCKET s = TLSServer::createSocket(8888);
    SSL_CTX* ctx = TLSServer::createContext();
    RSA* rsa = TLSServer::createRSA();
    TLSServer::configContext(ctx);
    TLSServer::Session sess;

    std::cout << "Server Up" << std::endl;

    // while (true) 
    // {
    struct sockaddr_in addr;
    int len = sizeof(addr);
    SSL* ssl;
    char buf[LENGTH];
    ZeroMemory(buf, LENGTH);

    int client = accept(s, (struct sockaddr*) & addr, &len);

    if (client > 0)
    {
      ssl = SSL_new(ctx);
      SSL_set_fd(ssl, client);

      if (SSL_accept(ssl) <= 0)
      {
        ERR_print_errors_fp(stdout);
      }
      else
      {
        std::cout << "connected" << std::endl;
      }
      // send auth
      while (true)
      {
        std::string s("Authenication Request");
        SSL_write(ssl, s.c_str(), s.size());
        // wait for password and user for client auth
        unsigned long res = SSL_read(ssl, buf, LENGTH);
        if (res > 0)
        {
          unsigned char user[32];
          unsigned char pass[32];
          std::string filename;
          std::cout << "Size of message : " << res << std::endl;
          std::cout << "Username is : ";
          for (int i = 0; i < 32; ++i)
          {
            user[i] = (unsigned char)buf[i];
            std::cout << (int)user[i] << ", ";
          }
          std::cout << std::endl;
          std::cout << "Password is : ";
          for (int i = 0; i < 32; ++i)
          {
            pass[i] = (unsigned char)buf[i + 32];
            std::cout << (int)pass[i] << ", ";
          }
          std::cout << std::endl;
          for (int i = 64; i < res; ++i) filename.push_back(buf[i]);
          std::cout << "Filename is : " << filename << std::endl;
          // check username and password and filename
          std::ifstream input(filename.c_str(), std::ios::binary);
          if (db.Authenticate(user, pass) && input.is_open())
          {
            std::cout << "Correct Username and Password" << std::endl;
            std::string message;
            message.push_back(1);

            std::string session = TLSServer::GenerateSessionKey();

            message += session;

            int p = 8080;
            int* ptmp = &p;
            char* ctmp = reinterpret_cast<char*>(ptmp);
            for (int i = 0; i < sizeof(int); ++i)
              message.push_back(ctmp[i]);

            sess.PortNum = p;
            sess.fn = filename;
            for (int i = 0; i < 32; ++i)
              sess.clientDataKey[i] = (unsigned char)session[i];

            for (int i = 0; i < 32; ++i)
              sess.clientMacKey[i] = (unsigned char)session[32 + i];

            for (int i = 0; i < 32; ++i)
              sess.serverDataKey[i] = (unsigned char)session[64 + i];

            for (int i = 0; i < 32; ++i)
              sess.serverMacKey[i] = (unsigned char)session[96 + i];

            for (int i = 0; i < 16; ++i)
              sess.snonce[i] = sess.cnonce[i] = i;

            sess.InitSocket();

            unsigned char  raw[2048] = {};
            unsigned char  encrypted[2048] = {};
            ZeroMemory(raw, 2048);
            ZeroMemory(encrypted, 2048);

            for (int i = 0; i < message.size(); ++i)
              raw[i] = message[i];

            int encrypted_length = RSA_private_encrypt(message.size(), raw, encrypted, rsa, RSA_PKCS1_PADDING);

            // generate session key and nonce and send to client
            SSL_write(ssl, encrypted, encrypted_length);
            input.close();
            break;
          }
          else
          {
            std::string message;
            message.push_back(0);

            unsigned char  raw[2048] = {};
            unsigned char  encrypted[2048] = {};
            ZeroMemory(raw, 2048);
            ZeroMemory(encrypted, 2048);

            for (int i = 0; i < message.size(); ++i)
              raw[i] = message[i];

            int encrypted_length = RSA_private_encrypt(message.size(), raw, encrypted, rsa, RSA_PKCS1_PADDING);

            SSL_write(ssl, encrypted, encrypted_length);
          }
        }
      }
      SSL_shutdown(ssl);
      SSL_free(ssl);
      closesocket(client);
    }
    else
    {
      perror("Unable to accept");
      exit(EXIT_FAILURE);
    }

    sess.Run();
    sess.ShutDown();

    // }
    TLSServer::shutDown(s, ctx);
    db.Close();
  }
#else
  // client
  TLSClient::initSSL();
  SSL_CTX* ctx = TLSClient::createContext();
  TLSClient::loadTrustStore(ctx);
  BIO* bio = TLSClient::createConnection(ctx);
  TLSClient::setConnection("192.168.1.83:8888", bio);
  SSL* ssl = TLSClient::setSSLMode(bio, ctx);
  std::cout << "Connected to server" << std::endl;
  RSA* rsa = TLSClient::createRSA(ssl);
  TLSClient::verifyConnection(ssl);
  TLSClient::CSession sess;

  char buf[LENGTH];
  ZeroMemory(buf, LENGTH);

  while (true)
  {
    ZeroMemory(buf, LENGTH);
    if (SSL_read(ssl, buf, LENGTH) > 0)
    {
      std::string res(buf);
      std::cout << buf << std::endl;
      if (res == "Authenication Request")
      {
        std::string user;
        std::string pass;
        std::string file;
        unsigned char userHash[32];
        unsigned char passHash[32];
        std::cout << "Please enter username" << std::endl;
        std::cin >> user;
        std::cout << "Please enter password" << std::endl;
        std::cin >> pass;
        std::cout << "Please enter filename" << std::endl;
        std::cin >> file;
        char* tmp = const_cast<char*>(user.c_str());
        unsigned char* uc = reinterpret_cast<unsigned char*>(tmp);
        SHA256(uc, user.size(), userHash);
        tmp = const_cast<char*>(pass.c_str());
        uc = reinterpret_cast<unsigned char*>(tmp);
        SHA256(uc, pass.size(), passHash);
        std::string message;
        std::cout << "Username is : ";
        for (int i = 0; i < 32; ++i)
        {
          std::cout << (int)userHash[i] << ", ";
          message.push_back(userHash[i]);
        }
        std::cout << std::endl;
        std::cout << "Password is : ";
        for (int i = 0; i < 32; ++i)
        {
          std::cout << (int)passHash[i] << ", ";
          message.push_back(passHash[i]);
        }
        std::cout << std::endl;
        message += file;
        SSL_write(ssl, message.c_str(), message.size());
        // need to read from the server for session key and nonce
        ZeroMemory(buf, LENGTH);
        int sz = SSL_read(ssl, buf, LENGTH);
        if (sz > 0)
        {
          unsigned char  decrypted[2048] = {};
          ZeroMemory(decrypted, 2048);
          int decryptedsize = RSA_public_decrypt(sz, (unsigned char*)buf, decrypted, rsa, RSA_PKCS1_PADDING);
          if (decrypted[0] == 1)
          {
            // need to set up session udp
            int counter = 0;

            std::cout << "Client Data Key : ";
            for (int i = 1; i < 33; ++i)
            {
              std::cout << (int)decrypted[i] << ", ";
              sess.clientDataKey[counter] = decrypted[i];
              ++counter;
            }
            std::cout << std::endl;
            counter = 0;

            std::cout << "Client Mac Key : ";
            for (int i = 33; i < 65; ++i)
            {
              std::cout << (int)decrypted[i] << ", ";
              sess.clientMacKey[counter] = decrypted[i];
              ++counter;
            }
            std::cout << std::endl;
            counter = 0;

            std::cout << "Server Data Key : ";
            for (int i = 65; i < 97; ++i)
            {
              std::cout << (int)decrypted[i] << ", ";
              sess.serverDataKey[counter] = decrypted[i];
              ++counter;
            }
            std::cout << std::endl;
            counter = 0;

            std::cout << "Server Mac Key : ";
            for (int i = 97; i < 129; ++i)
            {
              std::cout << (int)decrypted[i] << ", ";
              sess.serverMacKey[counter] = decrypted[i];
              ++counter;
            }
            std::cout << std::endl;
            counter = 0;

            int port = 0;
            int* portPtr = &port;
            char* tmp = reinterpret_cast<char*>(portPtr);

            for (int i = 129; i < sz; ++i)
            {
              *tmp = decrypted[i];
              if (i < 132)
                ++tmp;
            }
            sess.PortNum = port;
            std::cout << "Port is : " << sess.PortNum << std::endl;


            for (int i = 0; i < 16; ++i)
              sess.snonce[i] = sess.cnonce[i] = i;

            break;
          }
        }
      }
    }
  }

  sess.InitSocket();
  sess.Run();
  sess.ShutDown();

  TLSClient::shutDown(bio, ssl, ctx);
#endif
}