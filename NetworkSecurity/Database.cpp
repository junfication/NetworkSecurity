#include "Database.h"

int callback(void* data, int argc, char** argv, char** azColName)
{
  std::map<std::string, std::string>* map = static_cast<std::map<std::string, std::string>*>(data);

  if (!argv[0] || !argv[1]) return 0;

  std::string user = argv[0];
  std::string pass = argv[1];


  std::string username;
  std::string password;

  char* userChar = argv[0];
  char* passChar = argv[1];

  char* tok;
  tok = std::strtok(userChar, ",");
  while (tok != NULL)
  {
    int val = std::stoi(tok);
    username.push_back((unsigned char)val);
    tok = strtok(NULL, ",");
  }

  char* tok2;
  tok2 = std::strtok(passChar, ",");
  while (tok2 != NULL)
  {
    int val = std::stoi(tok2);
    password.push_back((unsigned char)val);
    tok2 = strtok(NULL, ",");
  }

  map->operator[](username) = password;

  return 0;
}

void Database::Open()
{
  int exit = 0;
  exit = sqlite3_open("Data.db", &DB);
  if (exit)
  {
    std::cout << "No Database File Found!" << std::endl;
    DB = nullptr;
    return;
  }
  else
    std::cout << "Opened Database Successfully!" << std::endl;
}

void Database::Load()
{
  if (DB)
  {
    users.clear();
    std::string sql("SELECT * FROM users");
    int rc = sqlite3_exec(DB, sql.c_str(), callback, (void*)&users, NULL);
    if (rc != SQLITE_OK) std::cout << "Error in loading" << std::endl;
  }
  else
    std::cout << "Database not Opened!" << std::endl;
}

void Database::Close()
{
  sqlite3_close(DB);
  DB = nullptr;
  users.clear();
}

void Database::Print()
{
  for (const auto& u : users)
    std::cout << u.first << " " << u.second << std::endl;
}

void Database::Add(std::string username, std::string password)
{
  std::string stmt = "INSERT INTO users VALUES ('";

  unsigned char userHash[32];
  unsigned char passHash[32];

  char* tmp = const_cast<char*>(username.c_str());
  unsigned char* uc = reinterpret_cast<unsigned char*>(tmp);
  SHA256(uc, username.size(), userHash);
  tmp = const_cast<char*>(password.c_str());
  uc = reinterpret_cast<unsigned char*>(tmp);
  SHA256(uc, password.size(), passHash);

  std::string hashUser;
  for (int i = 0; i < 32; ++i)
  {
    hashUser += std::to_string((int)userHash[i]);
    hashUser += ",";
  }

  std::string hashPass;
  for (int i = 0; i < 32; ++i)
  {
    hashPass += std::to_string((int)passHash[i]);
    hashPass += ",";
  }

  stmt += hashUser;
  stmt += "', '";
  stmt += hashPass;
  stmt += "')";
  if (DB) 
  {
    char* errorMsg = 0;
    int rc = sqlite3_exec(DB, stmt.c_str(), 0, 0, &errorMsg);
    if (rc != SQLITE_OK)
      std::cout << "Error adding username and password!" << std::endl;
    else
      std::cout << "Added username and password" << std::endl;
  }
  else
    std::cout << "Database not Opened!" << std::endl;
}

void Database::Delete(std::string username)
{
  std::string stmt = "DELETE from users WHERE Username = '";
  stmt += username;
  stmt += "'";
  if (DB)
  {
    char* errorMsg = 0;
    int rc = sqlite3_exec(DB, stmt.c_str(), 0, 0, &errorMsg);
    if (rc != SQLITE_OK)
      std::cout << "Error deleting username and password!" << std::endl;
    else
      std::cout << "Deleted username and password" << std::endl;
  }
  else
    std::cout << "Database not Opened!" << std::endl;
}

bool Database::Authenticate(unsigned char* user, unsigned char* pass)
{
  std::string username;
  std::string password;
  for (int i = 0; i < 32; ++i) username.push_back(user[i]);
  for (int i = 0; i < 32; ++i) password.push_back(pass[i]);
  auto res = users.find(username);
  if (res == users.end())
  {
    std::cout << "No such User" << std::endl;
    return false;
  }
  if (users[username] != password)
  {
    std::cout << "Wrong Password" << std::endl;
    return false;
  }
  return true;
}

std::map<std::string, std::string>* Database::GetData()
{
  return &users;
}
