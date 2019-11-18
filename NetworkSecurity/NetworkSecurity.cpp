// NetworkSecurity.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include "Connection.h"

int main()
{
  while (true)
  {
    std::cout << "Enter which appliction to be as 's' as Server, 'c' as client, 'd' to config database : ";
    std::string input;
    std::cin >> input;
    if (input == "s" || input == "S")
    {
      Server();
      break;
    }
    else if (input == "c" || input == "C")
    {
      Client();
      break;
    }
    else if (input == "d" || input == "D")
    {
      ConfigDatabase();
      std::cout << "Enter 'q' to exit application and any other key to access other options : ";
      std::string input2;
      std::cin >> input2;
      if (input2 == "q" || input2 == "Q")
        break;
    }
    else
      std::cout << "Wrong Input" << std::endl;
  }
}