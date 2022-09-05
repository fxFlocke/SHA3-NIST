#include <string>
#include <iostream>
#include "../Header/SHA3.h"

using namespace std;

int main()
{
    string input = "testing";
    string output = SHA3().hash(input);
    cout << output;
    return 0;
}