#include <string>
#include <bitset>
#include <iostream>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include "../header/SHA3.h"

using namespace std;

//Standard-Constructor
SHA3::SHA3()
{

}

//Destructor -> Needed by every class to destroy objects and release occupied memory
SHA3::~SHA3()
{

}

//Find number which the bits of a word are rotated, by the index of the word
int SHA3::find_rotation_index(int x, int y)
{
    int rotationIndex;
    switch(x)
            {
                case 0:
                {
                    switch(y)
                    {
                        case 0: rotationIndex = 0;
                                break;
                        case 1: rotationIndex = 36;
                                break;
                        case 2: rotationIndex = 3;
                                break;
                        case 3: rotationIndex = 41;
                                break;
                        case 4: rotationIndex = 18;
                                break;
                    }
                    break;
                }
                case 1:
                {
                    switch(y)
                    {
                        case 0: rotationIndex = 1;
                                break;
                        case 1: rotationIndex = 44;
                                break;
                        case 2: rotationIndex = 10;
                                break;
                        case 3: rotationIndex = 45;
                                break;
                        case 4: rotationIndex = 2;
                                break;
                    }
                    break;
                }
                case 2:
                {
                    switch(y)
                    {
                        case 0: rotationIndex = 62;
                                break;
                        case 1: rotationIndex = 6;
                                break;
                        case 2: rotationIndex = 43;
                                break;
                        case 3: rotationIndex = 15;
                                break;
                        case 4: rotationIndex = 61;
                                break;
                    }
                    break;
                }
                case 3:
                {
                    switch(y)
                    {
                        case 0: rotationIndex = 28;
                                break;
                        case 1: rotationIndex = 55;
                                break;
                        case 2: rotationIndex = 25;
                                break;
                        case 3: rotationIndex = 21;
                                break;
                        case 4: rotationIndex = 56;
                                break;
                    }
                    break;
                }
                case 4:
                {
                    switch(y)
                    {
                        case 0: rotationIndex = 27;
                                break;
                        case 1: rotationIndex = 20;
                                break;
                        case 2: rotationIndex = 39;
                                break;
                        case 3: rotationIndex = 8;
                                break;
                        case 4: rotationIndex = 14;
                                break;
                    }
                    break;
                }
            }
    return rotationIndex;
}

//Find the decimal number who needs to be added to the word at position 0,0
long long SHA3::find_jota_word(int round)
{
        long long result;
    switch(round)
    {
        case 0: result = 32907; break;
        case 1: result = 32898; break;
        case 2: result = 9223372036854808714; break;
        case 3: result = 9223372039002292224; break;
        case 4: result = 32907; break;
        case 5: result = 2147483649; break;
        case 6: result = 9223372039002292353; break;
        case 8: result = 138; break;
        case 9: result = 136; break;
        case 10: result = 2147516425; break;
        case 11: result = 2147483658; break;
        case 12: result = 2147516555; break;
        case 13: result = 9223372036854775947; break;
        case 14: result = 9223372036854808713; break;
        case 15: result = 9223372036854808579; break;
        case 16: result = 9223372036854808578; break;
        case 17: result = 9223372036854775936; break;
        case 18: result = 32778; break;
        case 19: result = 9223372039002259466; break;
        case 20: result = 9223372039002292353; break;
        case 21: result = 9223372036854808704; break;
        case 22: result = 2147483649; break;
        case 23: result = 9223372039002292232; break;
    }
    return result;
}

//Transform a Bit string to Hex-Code
string SHA3::bin_to_hex(string bits)
{
        string result = "";
    if(bits == "0000")
    {
        result = "0";
    }
    else if(bits == "0001")
    {
        result = "1";
    }
    else if(bits == "0010")
    {
        result = "2";
    }
    else if(bits == "0011")
    {
        result = "3";
    }
    else if(bits == "0100")
    {
        result = "4";
    }
    else if(bits == "0101")
    {
        result = "5";
    }
    else if(bits == "0110")
    {
        result = "6";
    }
    else if(bits == "0111")
    {
        result = "7";
    }
    else if(bits == "1000")
    {
        result = "8";
    }
    else if(bits == "1001")
    {
        result = "9";
    }
    else if(bits == "1010")
    {
        result = "A";
    }
    else if(bits == "1011")
    {
        result = "B";
    }
    else if(bits == "1100")
    {
        result = "C";
    }
    else if(bits == "1101")
    {
        result = "D";
    }
    else if(bits == "1110")
    {
        result = "E";
    }
    else if(bits == "1111")
    {
        result = "F";
    }
    return result;
}

//Rotate a Word of Bits by a number in the right direction
string SHA3::rotate_left(string word, int rotNum)
{
    reverse(word.begin(), word.begin() + rotNum);
    reverse(word.begin()+ rotNum, word.end());
    reverse(word.begin(), word.end());
    return word;
}

//Rotate a Word of Bits by a number in the left direction
string SHA3::rotate_right(string word, int rotNum)
{
    rotate_left(word, word.length() - rotNum);
    return word;
}

//Transform a text input to bits
string SHA3::text_to_binary_string(string words)
{
    string binaryString = "";
    for(char& _char : words)
    {
        binaryString += bitset<8>(_char).to_string();
    }
    return binaryString;
}

//Prepare the message for hashing with padding.
string SHA3::fillBits(string data)
{
        int size = data.size();
    data = data + "011";
    size = 26109 - size;
    for(int i = 1; i <= size; i++)
    {
        data = data + "0";
    }
    data = data + "1";
    return data;
}

//Perform a xor operation on a bit-string by the bitLength number
string SHA3::xor_operation(string firstBits, string secondBits, int bitLength)
{
        string result = "";
    for( int i = 0; i <= bitLength-1; i++)
    {
        if(firstBits[i] == secondBits[i])
        {
            result += "0";
        }
        else
        {
            result += "1";
        }
    }
    return result;
}

//Perform the Theta-Block
string SHA3::theta_block(string bits)
{
    //Set Variables
    string cube[5][5][64];
    string actualBitC, actualBitD, resultBits, bitOne, bitTwo, bitThree, bitFour, bitFive;
    int new_x_index, new_z_index;
    int counter = 0;
    //Transform the Bit-String in a 5x5x64 Block
    for( int x = 0; x <= 4; x++)
    {
        for(int y = 0; y <= 4; y++)
        {
            for(int z = 0; z <= 63; z++)
            {
                cube[x][y][z] = bits[counter];
                counter++;
            }
        }
    }
    //Perform the xor Step for every bit in the block
    for( int x = 0; x <= 4; x++)
    {
        for(int y = 0; y <= 4; y++)
        {
            for(int z = 0; z <= 63; z++)
            {

                //Calculate first D-Operator
                if(x == 0)
                {
                    new_x_index = 4;
                }
                else
                {
                    new_x_index = x-1;
                }
                //XOR Operation for 5 Bit-Pillar on the left
                bitOne = cube[new_x_index][0][z];
                bitTwo = cube[new_x_index][1][z];
                bitThree = cube[new_x_index][2][z];
                bitFour = cube[new_x_index][3][z];
                bitFive = cube[new_x_index][4][z];
                if((bitOne == bitTwo) && (bitTwo == bitThree) && (bitThree == bitFour) && (bitFour == bitFive))
                {
                    actualBitC = '0';
                }
                else
                {
                    actualBitC = '1';
                }
                //Calculate second D-Operator
                if(x == 4)
                {
                    new_x_index = 0;
                }
                else
                {
                    new_x_index = x + 1;
                }
                if(z == 0)
                {
                    new_z_index = 63;
                }
                else
                {
                    new_z_index = z-1;
                }
                //Perform XOR-Operation for 5 Bit Pillar on the right and one behind
                bitOne = cube[new_x_index][0][new_z_index];
                bitTwo = cube[new_x_index][1][new_z_index];
                bitThree = cube[new_x_index][2][new_z_index];
                bitFour = cube[new_x_index][3][new_z_index];
                bitFive = cube[new_x_index][4][new_z_index];
                if((bitOne == bitTwo) && (bitTwo == bitThree) && (bitThree == bitFour) && (bitFour == bitFive))
                {
                    actualBitD = '0';
                }
                else
                {
                    actualBitD = '1';
                }
                //XOR-Operation for the both Bit-Operators and the Outgoing-Bit
                actualBitD = xor_operation(actualBitC, actualBitD, 1);
                cube[x][y][z] = xor_operation(actualBitD, cube[x][y][z], 1);
            }
        }
    }
    //Bring Cube in String structure again
    for( int x = 0; x <= 4; x++)
    {
        for(int y = 0; y <= 4; y++)
        {
            for(int z = 0; z <= 63; z++)
            {
                resultBits += cube[x][y][z];
            }
        }
    }
    return resultBits;
}

string SHA3::rho_and_pi_block(string bits)
{
        string cube[5][5][64];
    string resultCube[5][5][64];
    string wordSaver, resultBits;
    int new_index, fromSubStr, rotationIndex;
    int countWords = 0;
    int countChars = 0;

    //Rho step -> Rotation
    for( int x = 0; x <= 4; x++)
    {
        for(int y = 0; y <= 4; y++)
        {
            //Find number for rotation
            rotationIndex = find_rotation_index(x, y);
            fromSubStr = countWords * 64;
            //Save word for the rotation
            wordSaver = bits.substr(fromSubStr, 64);
            //rotate word
            wordSaver = rotate_left(wordSaver, rotationIndex);
            countWords++;
            //Bring word in cube structure
            for(int z = 0; z <= 63; z++)
            {
                cube[x][y][z] = wordSaver[countChars];
                countChars++;
            }
            countChars = 0;
        }
    }

    //Pi step -> Permutation
    for( int x = 0; x <= 4; x++)
    {
        for(int y = 0; y <= 4; y++)
        {
            //Calculate new position in cube for word
            new_index = (2*x + 3*y) % 5;
            for(int z = 0; z <= 63; z++)
            {
                //Sort in the word
                resultCube[y][new_index][z] = cube[x][y][z];
            }
        }
    }
    //Bring the cube back in bitstring structure
    for( int x = 0; x <= 4; x++)
    {
        for(int y = 0; y <= 4; y++)
        {
            for(int z = 0; z <= 63; z++)
            {
                resultBits += resultCube[x][y][z];
            }
        }
    }
    return resultBits;
}

string SHA3::chi_block(string bits)
{
    //Set Variables
    string cube[5][5][64];
    string resultWord = "";
    string negationChar, secondChar, resultChar;
    int negationIndex, secondWordIndex;
    int counter = 0;
    //Bring string in block structure
    for( int x = 0; x <= 4; x++)
    {
        for(int y = 0; y <= 4; y++)
        {
            for(int z = 0; z <= 63; z++)
            {
                cube[x][y][z] = bits[counter];
                counter++;
            }
        }
    }
    for( int x = 0; x <= 4; x++)
    {
        for(int y = 0; y <= 4; y++)
        {
            //Calculate indexes for the operating bits
            if(x >= 3)
            {
                switch(x)
                {
                    case 3: negationIndex = 4;
                            secondWordIndex = 0;
                            break;
                    case 4: negationIndex = 0;
                            secondWordIndex = 1;
                            break;
                }
            }
            else
            {
                negationIndex = x + 1;
                secondWordIndex = x + 2;
            }
            // Perform the bit operations
            for(int z = 0; z <= 63; z++)
            {
                //Negation of the first operator
                if(cube[negationIndex][y][z] == "0")
                {
                    negationChar = "1";
                }
                else
                {
                    negationChar = "0";
                }
                //Get the second operator
                secondChar = cube[secondWordIndex][y][z];
                //Add both operators for the result
                if(negationChar == secondChar)
                {
                    resultChar = "1";
                }
                else
                {
                    resultChar = "0";
                }
                //Do the XOR-Operation for the result-bit and the outgoing bit
                resultChar = xor_operation(resultChar, cube[x][y][z], 1);
                //Add the result to the return string
                resultWord += resultChar;
            }
        }
    }
    return resultWord;
}

string SHA3::jota_block(string bits, int round)
{
    //Set variables
    //Find Number to add
    long long firstOperator = find_jota_word(round);
    string firstOpString, secOpString, tempString;
    secOpString = bits.substr(0, 64);
    int overflow = 0;
    //Bring number to bitstring structure
    firstOpString = bitset<64>(firstOperator).to_string();
    string binary = "";
    for(int i = 0; i <= 63; i++)
    {
        //Do the Add-Operation for the operators
        if(firstOpString[i] == secOpString[i])
        {
            if(overflow == 0)
            {
                binary += '0';
                if(firstOpString[i] == '1')
                {
                    overflow = 1;
                }
            }
            else
            {
                binary += '1';
                if(firstOpString[i] == '0')
                {
                    overflow = 0;
                }
            }
        }
        else
        {
            if(overflow == 1)
            {
                binary += '0';
                overflow = 0;
            }
            else 
            {
                binary += '1';
            }
        }
    }
    tempString = bits.substr(64, 1536);
    //Insert the new word into the existing string
    bits = binary + tempString;
    return bits;
}

string SHA3::f_function(string bits, int round)
{
    string bitBlock = bits;
    bitBlock = theta_block(bitBlock);
    bitBlock = rho_and_pi_block(bitBlock);
    bitBlock = chi_block(bitBlock);
    bitBlock = jota_block(bitBlock, round);
    return bitBlock;
}

string SHA3::hash(string message)
{
    string input = message;
    string injectionBlocks[23];
    string rPart, cPart, inputCopy, secondCopy, blockPart, tempWord;
    int fromSubStr, toSubStr;
    input = text_to_binary_string(input);
    if(input.size() > 1600)
    {
        std::cout << "Input is too big for the hash-function";
    }
    else
    {
        //Preprocessing -> Padding
        if(input.size() < 1600)
        {
            input = fillBits(input);
        }
        inputCopy = input;
        //Preprocessing -> Divide into 24 1088 Blocks
        for(int i = 0; i <= 23; i++)
        {
            fromSubStr = i * 1088;
            injectionBlocks[i] = input.substr(fromSubStr, 1088);
        }
        //Perform the 24 Rounds
        for(int i = 0; i <= 23; i++)
        {
            rPart = inputCopy.substr(0, 1088);
            cPart = inputCopy.substr(1088, 512);
            blockPart = injectionBlocks[0];
            rPart = xor_operation(rPart, blockPart, rPart.size());
            tempWord = rPart + cPart;
            inputCopy = f_function(tempWord, 0);
        }
        //Get the 256 Bit result
        rPart = inputCopy.substr(832, 256);
        string keccHash = "";
        //Transform string to Hex-format
        for(int i = 0; i <= 64; i++)
        {
            fromSubStr = i * 4;
            tempWord = rPart.substr(fromSubStr, 4);
            tempWord = bin_to_hex(tempWord);
            keccHash += tempWord;
        }
        //Return the result
        return keccHash;
    }
}