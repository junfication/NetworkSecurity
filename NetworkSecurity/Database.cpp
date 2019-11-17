#include "Database.h"

int callback(void* data, int argc, char** argv, char** azColName)
{
  std::map<std::string, std::string>* map = static_cast<std::map<std::string, std::string>*>(data);

  if (!argv[0] || !argv[1]) return 0;

  std::string user = argv[0];
  std::string pass = argv[1];

  unsigned char userHash[32];
  unsigned char passHash[32];

  char* tmp = const_cast<char*>(user.c_str());
  unsigned char* uc = reinterpret_cast<unsigned char*>(tmp);
  SHA256(uc, user.size(), userHash);
  tmp = const_cast<char*>(pass.c_str());
  uc = reinterpret_cast<unsigned char*>(tmp);
  SHA256(uc, pass.size(), passHash);

  std::string username;
  std::string password;

  for (int i = 0; i < 32; ++i)
  {
    username.push_back(userHash[i]);
  }

  for (int i = 0; i < 32; ++i)
  {
    password.push_back(passHash[i]);
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
  stmt += username;
  stmt += "', '";
  stmt += password;
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
