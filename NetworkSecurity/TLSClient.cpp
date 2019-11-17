#include "TLSClient.h"
#include <vector>
#include <fstream>

void TLSClient::initSSL()
{
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, 0);
  ERR_load_BIO_strings();
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
}

SSL_CTX* TLSClient::createContext()
{
  const SSL_METHOD* method;
  SSL_CTX* ctx;

  method = SSLv23_client_method();

  ctx = SSL_CTX_new(method);
  if (!ctx)
  {
    std::cout << "Unable to create context" << std::endl;
    ERR_print_errors_fp(stdout);
    exit(EXIT_FAILURE);
  }
  return ctx;
}

void TLSClient::loadTrustStore(SSL_CTX* ctx)
{
  if (!SSL_CTX_load_verify_locations(ctx, NULL, "cert.pem"))
  {
    std::cout << "Cannot load Trust Store" << std::endl;
    ERR_print_errors_fp(stdout);
    exit(EXIT_FAILURE);
  }
  else
  {
    std::cout << "Loaded Trust Store" << std::endl;
  }

}

BIO* TLSClient::createConnection(SSL_CTX* ctx)
{
  BIO* bio = BIO_new_ssl_connect(ctx);
  return bio;
}

void TLSClient::setConnection(std::string s, BIO* bio)
{
  BIO_set_conn_hostname(bio, s.c_str());
  if (BIO_do_connect(bio) <= 0)
  {
    std::cout << "Error in connecting to host" << std::endl;
    ERR_print_errors_fp(stdout);
    exit(EXIT_FAILURE);
  }
}

SSL* TLSClient::setSSLMode(BIO* bio, SSL_CTX* ctx)
{
  SSL* ssl = SSL_new(ctx);
  BIO_get_ssl(bio, &ssl);
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  return ssl;
}

void TLSClient::verifyConnection(SSL* ssl)
{
  // auto cert = SSL_get_peer_certificate(ssl);
  // if (cert)
  // {
  //   X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, 0);
  //   std::cout << std::endl;
  //   X509_free(cert);
  // }

  long res = SSL_get_verify_result(ssl);
  if (res != X509_V_OK && res != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
  {
    std::cout << "Certificate is invalid code : "<< res << std::endl;
    ERR_print_errors_fp(stdout);
    exit(EXIT_FAILURE);
  }
  if (res == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
  {
    std::cout << "Yes the certificate is self signed" << std::endl;
  }
}

void TLSClient::shutDown(BIO* bio, SSL* ssl, SSL_CTX* ctx)
{
  SSL_CTX_free(ctx);
  BIO_free_all(bio);
}

RSA* TLSClient::createRSA(SSL* ssl)
{
  RSA* rsa = RSA_new();
  FILE* fp = fopen("cert.pem", "rb");
  auto cert = SSL_get_peer_certificate(ssl);
  EVP_PKEY* tmp = EVP_PKEY_new();
  tmp = X509_get_pubkey(cert);
  rsa = EVP_PKEY_get1_RSA(tmp);
  fclose(fp);
  return rsa;
}

void TLSClient::CSession::InitSocket()
{
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
  {
    std::cout << "WSAStartup Failed" << std::endl;
    exit(EXIT_FAILURE);
  }

  if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
  {
    std::cout << "Cannot Create Socket" << std::endl;
    exit(EXIT_FAILURE);
  }

  u_long iMode = 0;
  ioctlsocket(s, FIONBIO, &iMode);

  ZeroMemory(&server, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = htons((unsigned short)PortNum);
  server.sin_addr.S_un.S_addr = inet_addr("192.168.1.83");
}

void TLSClient::CSession::Send()
{
  std::string message = Encrypt();
  std::cout << message.size() << std::endl;
  int r = sendto(s, message.c_str(), message.size(), 0, (sockaddr*)&server, sizeof(server));
  if (r < 0)
  {
    std::cout << "Error in sendto" << std::endl;
    std::cout << WSAGetLastError() << std::endl;
  }
  else
    std::cout << "Client Sent" << std::endl;
}

void TLSClient::CSession::Recieve()
{
  // Recv from client
  ZeroMemory(buf, 2048);
  int addrlen = sizeof(client);

  int r = recvfrom(s, buf, 2048, 0, (sockaddr*)&client, &addrlen);
  if (r > 0)
  {
    std::cout << "Client Recieved : " << r << std::endl;
    std::string msg;
    for (int i = 0; i < r; ++i)
      msg.push_back(buf[i]);
    Decrypt(msg);
  }
  else
  {
    std::cout << "Error in recv from" << std::endl;
    std::cout << WSAGetLastError() << std::endl;
  }
}

void TLSClient::CSession::ShutDown()
{
  closesocket(s);
  WSACleanup();
}

std::string TLSClient::CSession::Encrypt()
{
  std::string message;
  std::vector<unsigned char> input;

  if (!b)
  {
    input.push_back('s');
    input.push_back('t');
    input.push_back('a');
    input.push_back('r');
    input.push_back('t');
  }
  else
  {
    if (auth == 0)
      input.push_back(0);
    else
      input.push_back(1);
  }

  unsigned char output[2048];
  ZeroMemory(output, 2048);
  int outputSize = 0;
  int tmpoutSize = 0;

  EVP_CIPHER_CTX* ctx;
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clientDataKey, cnonce);
  EVP_EncryptUpdate(ctx, output, &outputSize, input.data(), input.size());
  EVP_EncryptFinal_ex(ctx, output + outputSize, &tmpoutSize);
  outputSize += tmpoutSize;
  EVP_CIPHER_CTX_free(ctx);

  unsigned char macoutput[2048];
  ZeroMemory(macoutput, 2048);
  int macoutputSize = 0;
  int tmpmacoutSize = 0;

  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clientMacKey, cnonce);
  EVP_EncryptUpdate(ctx, macoutput, &macoutputSize, input.data(), input.size());
  EVP_EncryptFinal_ex(ctx, macoutput + macoutputSize, &tmpmacoutSize);
  macoutputSize += tmpmacoutSize;
  EVP_CIPHER_CTX_free(ctx);

  for (int j = 0; j < outputSize; ++j)
    std::cout << (int)output[j] << ", ";
  std::cout << std::endl;

  for (int j = 0; j < macoutputSize; ++j)
    std::cout << (int)macoutput[j] << ", ";
  std::cout << std::endl;

  if (!b)
  {
    int tmpLen = 0;
    int* len = &tmpLen;
    char* tmp = reinterpret_cast<char*>(len);
    message.resize(sizeof(int));
    for (int i = 0; i < sizeof(int); ++i)
    {
      message[i] = *tmp;
      ++tmp;
    }
    std::cout << "sending start" << std::endl;
  }
  else
  {
    int* len = &outputSize;
    char* tmp = reinterpret_cast<char*>(len);
    message.resize(sizeof(int));
    for (int i = 0; i < sizeof(int); ++i)
    {
      message[i] = *tmp;
      ++tmp;
    }
  }

  for (int i = 0; i < outputSize; ++i)
    message.push_back(output[i]);
  for (int i = 0; i < macoutputSize; ++i)
    message.push_back(macoutput[i]);

  if (!b)
    b = true;
  
  Incrementcnonce();

  return message;
}

void TLSClient::CSession::Decrypt(std::string msg)
{
  char* tmp = const_cast<char*>(msg.c_str());
  int len = 0;
  int* tmpLen = &len;
  char* length = reinterpret_cast<char*>(tmpLen);
  for (int i = 0; i < sizeof(int); ++i)
  {
    *length = msg[i];
    if (i < sizeof(int) - 1)
      ++length;
  }

  std::cout << "Length is : " << len << std::endl;

  if (len == 0)
  {
    // check start message
    std::vector<unsigned char> input;

    input.push_back('S');
    input.push_back('h');
    input.push_back('u');
    input.push_back('t');
    input.push_back('d');
    input.push_back('o');
    input.push_back('w');
    input.push_back('n');

    unsigned char output[2048];
    ZeroMemory(output, 2048);
    int outputSize = 0;
    int tmpoutSize = 0;

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, serverDataKey, snonce);
    EVP_EncryptUpdate(ctx, output, &outputSize, input.data(), input.size());
    EVP_EncryptFinal_ex(ctx, output + outputSize, &tmpoutSize);
    outputSize += tmpoutSize;
    EVP_CIPHER_CTX_free(ctx);

    unsigned char macoutput[2048];
    ZeroMemory(macoutput, 2048);
    int macoutputSize = 0;
    int tmpmacoutSize = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, serverMacKey, snonce);
    EVP_EncryptUpdate(ctx, macoutput, &macoutputSize, input.data(), input.size());
    EVP_EncryptFinal_ex(ctx, macoutput + macoutputSize, &tmpmacoutSize);
    macoutputSize += tmpmacoutSize;
    EVP_CIPHER_CTX_free(ctx);

    int it = 0;
    int it2 = 0;
    int i = 4;

    for (; i < msg.size(); ++i)
    {
      if (it < outputSize)
      {
        if ((unsigned char)msg[i] != output[it])
        {
          std::cout << "ShutDown Data do not match" << std::endl;
          break;
        }
        ++it;
      }
      else
      {
        if ((unsigned char)msg[i] != macoutput[it2])
        {
          std::cout << "ShutDown MAC do not match" << std::endl;
          break;
        }
        ++it2;
      }
    }

    if (i == msg.size())
    {
      // set shutdown
      fin = true;
    }

  }
  else
  {
    // check authentication
    std::vector<unsigned char> input;
    std::string macCode;

    int i = 0;

    for (; i < len; ++i)
      input.push_back(msg[i + 4]);

    i += 4;

    for (; i < msg.size(); ++i)
      macCode.push_back(msg[i]);

    unsigned char output[2048];
    ZeroMemory(output, 2048);
    int outputSize = 0;
    int tmpoutSize = 0;

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, serverDataKey, snonce);
    EVP_DecryptUpdate(ctx, output, &outputSize, input.data(), input.size());
    EVP_DecryptFinal_ex(ctx, output + outputSize, &tmpoutSize);
    outputSize += tmpoutSize;
    EVP_CIPHER_CTX_free(ctx);

    unsigned char macoutput[2048];
    ZeroMemory(macoutput, 2048);
    int macoutputSize = 0;
    int tmpmacoutSize = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, serverMacKey, snonce);
    EVP_EncryptUpdate(ctx, macoutput, &macoutputSize, output, outputSize);
    EVP_EncryptFinal_ex(ctx, macoutput + macoutputSize, &tmpmacoutSize);
    macoutputSize += tmpmacoutSize;
    EVP_CIPHER_CTX_free(ctx);

    std::string generatedMaccode;

    for (int i = 0; i < macoutputSize; ++i)
      generatedMaccode.push_back(macoutput[i]);

    if (generatedMaccode == macCode)
    {
      std::cout << "Authenticated" << std::endl;
      for (int i = 0; i < outputSize; ++i)
        data.push_back(output[i]);
      auth = 1;
    }
    else
    {
      std::cout << "Not Authenticated" << std::endl;
      std::cout << "DeCrypted text : size : " << outputSize << " value : ";
      for (int i = 0; i < outputSize; ++i)
        std::cout << output[i];
      std::cout << std::endl;
      auth = 0;
    }

  }

  Incrementsnonce();
}

void TLSClient::CSession::Incrementsnonce()
{
  int i = 15;
  while (i >= 0 && !(++snonce[i]))
    --i;
}

void TLSClient::CSession::Incrementcnonce()
{
  int i = 15;
  while (i >= 0 && !(++cnonce[i]))
    --i;
}

void TLSClient::CSession::Run()
{
 // Send();
 // Recieve();
 while (!fin)
 {
   Send();
   Recieve();
 }
 Save();
}

void TLSClient::CSession::Save()
{
  std::ofstream file("Clientoutput.txt", std::ios::binary);
  file << data;
  file.close();
}
