#pragma once
#include <string>
#include "sqlite/sqlite3.h"
#include <map>
#include <iostream>

int callback(void* data, int argc, char** argv, char** azColName);

struct Database
{
  void Open();
  void Load();
  void Close();
  void Print();
  void Add(std::string username, std::string password);
  void Delete(std::string username);
  std::map<std::string, std::string>* GetData();
private:
  std::string sql = "SELECT * from users";
  sqlite3* DB = nullptr;
  std::map<std::string, std::string> users;
};



