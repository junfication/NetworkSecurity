#pragma once
#include <iostream>
#include <fstream>
#include <map>
#include "TLSServer.h"
#include "TLSClient.h"
#define LENGTH 2048
#include <openssl/sha.h>
#include <openssl/rsa.h>

void Server();
void Client();
void ConfigDatabase();