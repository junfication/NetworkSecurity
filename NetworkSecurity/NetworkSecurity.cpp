// NetworkSecurity.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include <iostream>
#include "Database.h"
#include <map>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main()
{
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, 0);
  ERR_load_BIO_strings();
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
  BIO* bio;
  bio = BIO_new_connect("192.168.1.83:8080");
  if (bio == NULL)
  {
    std::cout << "Failed to connect" << std::endl;
  }
  else if (BIO_do_connect(bio) <= 0)
  {
    std::cout << "Failed connection" << std::endl;
  }
  else
  {
    std::cout << "Connected!" << std::endl;
  }
  BIO_free_all(bio);
    std::cout << "Hello World!\n";
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
