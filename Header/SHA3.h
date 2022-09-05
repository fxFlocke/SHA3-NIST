#pragma once
#include <string>

using namespace std;

class SHA3
{
    public:
        SHA3();
        ~SHA3();
        string hash(string message);
        
    private:
        int find_rotation_index(int x, int y);
        long long find_jota_word(int round);
        string bin_to_hex(string bits);
        string rotate_left(string word, int rotNum);
        string rotate_right(string word, int rotNum);
        string text_to_binary_string(string words);
        string fillPadding(string data);
        string fillMessage(string data);
        string xor_operation(string firstBits, string secondBits, int bitLength);
        string theta_block(string bits);
        string rho_and_pi_block(string bits);
        string chi_block(string bits);
        string jota_block(string bits, int round);
        string f_function(string bits, int round);
};