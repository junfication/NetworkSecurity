#include "Database.h"

int callback(void* data, int argc, char** argv, char** azColName)
{
  std::map<std::string, std::string>* map = static_cast<std::map<std::string, std::string>*>(data);

  if (!argv[0] || !argv[1]) return 0;

  std::string username = argv[0];
  std::string password = argv[1];

  map->operator[](username) = password;

  printf("\n");
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

std::map<std::string, std::string>* Database::GetData()
{
  return &users;
}
