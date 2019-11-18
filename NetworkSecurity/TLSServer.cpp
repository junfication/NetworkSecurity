#include "TLSServer.h"
#include <vector>
#define BLOCK_SIZE 500

SOCKET TLSServer::createSocket(int port)
{
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s < 0)
  {
    std::cout << "Error creating socket" << std::endl;
    exit(EXIT_FAILURE);
  }

  if (bind(s, (struct sockaddr*) & addr, sizeof(addr)) < 0)
  {
    std::cout << "Error in binding socket" << std::endl;
    exit(EXIT_FAILURE);
  }

  if (listen(s, 1) < 0)
  {
    std::cout << "Error in listening" << std::endl;
    exit(EXIT_FAILURE);
  }
  return s;
}

void TLSServer::initSSL()
{
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, 0);
  ERR_load_BIO_strings();
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
}

void TLSServer::initWinsock(WSADATA* wsa)
{
  if (WSAStartup(MAKEWORD(2, 2), wsa) != 0)
  {
    std::cout << "WSAStartup Failed" << std::endl;
    exit(EXIT_FAILURE);
  }
}

void TLSServer::shutDown(SOCKET s, SSL_CTX* ctx)
{
  closesocket(s);
  SSL_CTX_free(ctx);
  WSACleanup();
}

SSL_CTX* TLSServer::createContext()
{
  const SSL_METHOD* method;
  SSL_CTX* ctx;

  method = SSLv23_server_method();

  ctx = SSL_CTX_new(method);
  if (!ctx)
  {
    std::cout << "Unable to create context" << std::endl;
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  return ctx;
}

void TLSServer::configContext(SSL_CTX* ctx)
{
  if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) 
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) 
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_check_private_key(ctx) <= 0)
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

RSA* TLSServer::createRSA()
{
  RSA* rsa = RSA_new();
  FILE* fp = fopen("key.pem", "rb");
  rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
  fclose(fp);
  return rsa;
}

std::string TLSServer::GenerateSessionKey()
{
  std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
  std::uniform_int_distribution<int>dis(0, 255);
  std::string session;
  unsigned char salt[] = "0";
  salt[0] = (unsigned char)dis(rng);
  unsigned char clientDataKey[SHA256_DIGEST_LENGTH];
  unsigned char clientMacKey[SHA256_DIGEST_LENGTH];
  unsigned char serverDataKey[SHA256_DIGEST_LENGTH];
  unsigned char serverMacKey[SHA256_DIGEST_LENGTH];

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, salt, 1);
  SHA256_Final(clientDataKey, &sha256);

  salt[0] = (unsigned char)dis(rng);
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, salt, 1);
  SHA256_Final(clientMacKey, &sha256);

  salt[0] = (unsigned char)dis(rng);
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, salt, 1);
  SHA256_Final(serverDataKey, &sha256);

  salt[0] = (unsigned char)dis(rng);
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, salt, 1);
  SHA256_Final(serverMacKey, &sha256);
  
  std::cout << "Client Data Key : ";
  for (unsigned i = 0; i < SHA256_DIGEST_LENGTH; ++i)
  {
    std::cout << (int)clientDataKey[i] << ", ";
    session.push_back(clientDataKey[i]);
  }
  std::cout << std::endl;

  std::cout << "Client Mac Key : ";
  for (unsigned i = 0; i < SHA256_DIGEST_LENGTH; ++i)
  {
    std::cout << (int)clientMacKey[i] << ", ";
    session.push_back(clientMacKey[i]);
  }
  std::cout << std::endl;

  std::cout << "Server Data Key : ";
  for (unsigned i = 0; i < SHA256_DIGEST_LENGTH; ++i)
  {
    std::cout << (int)serverDataKey[i] << ", ";
    session.push_back(serverDataKey[i]);
  }
  std::cout << std::endl;

  std::cout << "Server Mac Key : ";
  for (unsigned i = 0; i < SHA256_DIGEST_LENGTH; ++i)
  {
    std::cout << (int)serverMacKey[i] << ", ";
    session.push_back(serverMacKey[i]);
  }
  std::cout << std::endl;

  return session;
}

std::string TLSServer::GenerateNonces()
{
  std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
  std::uniform_int_distribution<int>dis(0, 255);
  std::string nonceString;
  unsigned char salt[] = "0";
  salt[0] = (unsigned char)dis(rng);
  unsigned char nonces[SHA256_DIGEST_LENGTH];

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, salt, 1);
  SHA256_Final(nonces, &sha256);

  for (unsigned i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    nonceString.push_back(nonces[i]);

  return nonceString;
}

void TLSServer::PrintHostNameAndIP()
{
  char hostbuffer[256];
  char* IPbuffer;
  struct hostent* host_entry;
  int hostname;

  // To retrieve hostname 
  hostname = gethostname(hostbuffer, sizeof(hostbuffer));

  // To retrieve host information 
  host_entry = gethostbyname(hostbuffer);

  // To convert an Internet network 
  // address into ASCII string 
  IPbuffer = inet_ntoa(*((struct in_addr*)
    host_entry->h_addr_list[0]));

  printf("Hostname: %s\n", hostbuffer);
  printf("Host IP: %s\n", IPbuffer);
}

void TLSServer::Session::InitSocket()
{
  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
  {
    std::cout << "Cannot Create Socket" << std::endl;
    exit(EXIT_FAILURE);
  }
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons((unsigned short)PortNum);

  u_long iMode = 0;
  ioctlsocket(s, FIONBIO, &iMode);

  if (bind(s, (struct sockaddr*) &server, sizeof(server)) == SOCKET_ERROR)
  {
    closesocket(s);
    std::cout << "Cannot Bind Socket" << std::endl;
    exit(EXIT_FAILURE);
  }
  std::ifstream input(fn.c_str(), std::ios::binary);
  std::string inputData(std::istreambuf_iterator<char>(input), {});
  data = inputData;
  // std::cout << "Data is : " << data << std::endl;
  input.close();
}

void TLSServer::Session::Send()
{
  std::string message = Encrypt();
  std::cout << "Message Size : " << message.size() << std::endl;
  // Send to client
  if (b)
  {
    int r = sendto(s, message.c_str(), message.size(), 0, (struct sockaddr*)&client, sizeof(client));
    if (r > 0)
      std::cout << "Server Sent : " << r << std::endl;
    else
      std::cout << "Sent to error" << std::endl;
  }
}

void TLSServer::Session::Recieve()
{
  // Recv from client
  ZeroMemory(buf, 2048);
  int addrlen = sizeof(client);

  int r = recvfrom(s, buf, 2048, 0, (struct sockaddr*)&client, &addrlen);
  if (r > 0)
  {
    std::cout << "Server Recieved : " << r << std::endl;
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

void TLSServer::Session::ShutDown()
{
  closesocket(s);
}

std::string TLSServer::Session::Encrypt()
{
  std::string message;
  std::vector<unsigned char> input;

  if (it < data.size())
  {
    for (int i = 0; i < BLOCK_SIZE && it < data.size(); ++i)
    {
      input.push_back(data[it]);
      ++it;
    }
    std::cout << "IT is " << it << std::endl;
  }
  else
  {
    input.push_back('S');
    input.push_back('h');
    input.push_back('u');
    input.push_back('t');
    input.push_back('d');
    input.push_back('o');
    input.push_back('w');
    input.push_back('n');
    fin = true;
  }

  unsigned char output[2048];
  ZeroMemory(output, 2048);
  int outputSize = 0;
  int tmpOutSize = 0;

  EVP_CIPHER_CTX* ctx;
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, serverDataKey, snonce);
  EVP_EncryptUpdate(ctx, output, &outputSize, input.data(), input.size());
  EVP_EncryptFinal_ex(ctx, output + outputSize, &tmpOutSize);
  outputSize += tmpOutSize;
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

  if (!fin)
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
  else
  {
    std::cout << "output size : " << outputSize << std::endl;
    std::cout << "mac output size : " << macoutputSize << std::endl;

    int tmpLen = 0;
    int* len = &tmpLen;
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

  Incrementsnonce();

  return message;
}

void TLSServer::Session::Decrypt(std::string msg)
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
  
  std::cout << "LEngth is " << len << std::endl;

  if (len == 0)
  {
    std::cout << "Check start" << std::endl; 
    // check start message
    std::vector<unsigned char> input;

    input.push_back('s');
    input.push_back('t');
    input.push_back('a');
    input.push_back('r');
    input.push_back('t');

    unsigned char output[2048];
    ZeroMemory(output, 2048);
    int outputSize = 0;
    int tmpOutSize = 0;

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clientDataKey, cnonce);
    EVP_EncryptUpdate(ctx, output, &outputSize, input.data(), input.size());
    EVP_EncryptFinal_ex(ctx, output + outputSize, &tmpOutSize);
    outputSize += tmpOutSize;
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

    int it = 0;
    int it2 = 0;
    int i = 4;

    for (int j = 0; j < outputSize; ++j)
      std::cout << (int)output[j] << ", ";
    std::cout << std::endl;

    for (int j = 0; j < macoutputSize; ++j)
      std::cout << (int)macoutput[j] << ", ";
    std::cout << std::endl;

    for (; i < msg.size(); ++i)
    {
      if (it < outputSize)
      {
        if ((unsigned char)msg[i] != output[it])
        {
          std::cout << "Start Data do not match" << std::endl;
          break;
        }
        ++it;
      }
      else
      {
        if ((unsigned char)msg[i] != macoutput[it2])
        {
          std::cout << "Start MAC do not match" << std::endl;
          break;
        }
        ++it2;
      }
    }

    if (i == msg.size())
    {
      // set start
      b = true;
    }
    else
      std::cout << "Does not match" << std::endl;

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
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clientDataKey, cnonce);
    EVP_DecryptUpdate(ctx, output, &outputSize, input.data(), input.size());
    EVP_DecryptFinal_ex(ctx, output + outputSize, &tmpoutSize);
    outputSize += tmpoutSize;
    EVP_CIPHER_CTX_free(ctx);

    unsigned char macoutput[2048];
    ZeroMemory(macoutput, 2048);
    int macoutputSize = 0;
    int tmpmacoutSize = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clientMacKey, cnonce);
    EVP_EncryptUpdate(ctx, macoutput, &macoutputSize, output, outputSize);
    EVP_EncryptFinal_ex(ctx, macoutput + macoutputSize, &tmpmacoutSize);
    macoutputSize += tmpmacoutSize;
    EVP_CIPHER_CTX_free(ctx);

    std::string generatedMaccode;

    for (int i = 0; i < macoutputSize; ++i)
      generatedMaccode.push_back(macoutput[i]);

    if (generatedMaccode == macCode)
    {
      if (output[0] == 1)
      {
        std::cout << "Authenticated" << std::endl;
      }
      else
      {
        std::cout << "Not Authenticated" << std::endl;
        unsigned int res = it % BLOCK_SIZE;
        if (!res) it -= BLOCK_SIZE;
        else it -= res;
      }
    }

  }

  Incrementcnonce();
}

void TLSServer::Session::Incrementsnonce()
{
  int i = 15;
  while (i >= 0 && !(++snonce[i]))
    --i;
}

void TLSServer::Session::Incrementcnonce()
{
  int i = 15;
  while (i >= 0 && !(++cnonce[i]))
    --i;
}

void TLSServer::Session::Run()
{
  while (!fin)
  {
    Recieve();
    Send();
  }
}
