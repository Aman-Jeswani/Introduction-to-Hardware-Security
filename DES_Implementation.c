#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>


// Function Prototypes

// For the Cipher Function and main computation
// Initial Permutation
void initialPermutation(bool*, unsigned char*, bool*, bool*);

// Function to print the vector
void printVector(bool*, unsigned char);

// Separate the right and left parts
void separate_RL(bool*, unsigned char, bool*, bool*);

// Combine the right and left parts
void join_RL(bool*, unsigned char, bool*, bool*);

// Expansion for the Cipher Function
void expand_E(bool*, unsigned char*, bool*);

// xor operation
void XOR(bool*, bool*, unsigned char, bool*);

// Selection Function
void primitiveSelection(bool*, unsigned char[][4][16], bool*);

// Convert Character to Boolean
void char2Bool(unsigned char, bool*, unsigned char);

// Cipher Function
void cipherFunction(bool*, bool*, unsigned char*, unsigned char[][4][16], unsigned char*, bool*);

// Inverse Permutation
void inversePermutation(bool*, unsigned char*, bool*);


// For the Key Schedule
// Permuted Choice 1
void permutedChoice1(bool*, unsigned char*, bool*);

// Permuted Choice 2
void permutedChoice2(bool*, unsigned char*, bool*);

// Left Shift
void shift_Left(bool*, unsigned char, bool*);


// Function Definitions
// permutedChoice1
void permutedChoice1(bool* key, unsigned char* PC1, bool* newKey)
{
unsigned char i;
for (i = 0; i < 56; i++)
{
    newKey[i] = key[PC1[i] - 1];
}
}

// permutedChoice2
void permutedChoice2(bool* key, unsigned char* PC2, bool* newKey)
{
unsigned char i;
for (i = 0; i < 48; i++)
{
    newKey[i] = key[PC2[i] - 1];
}
}

// permute_P
void permute_P(bool* SmR, unsigned char* P, bool* PmR)
{
unsigned char i;
for (i = 0; i < 32; i++)
{
PmR[i] = SmR[P[i] - 1];
}
}

// initialPermutation
void initialPermutation(bool* plaintext, unsigned char* IP_, bool* newMessageR, bool* newMessageL)
{
bool newMessage[64];
unsigned char i;
for (i = 0; i < 64; i++)
{
newMessage[i] = plaintext[IP_[i] - 1];
}

separate_RL(newMessage, 64, newMessageR, newMessageL);
}

// inversePermutation
void inversePermutation(bool* PreCrypto, unsigned char* IPInv, bool* Cipher)
{
unsigned char i;
for (i = 0; i < 64; i++)
{
Cipher[i] = PreCrypto[IPInv[i] - 1];
}
}

// expand_E
void expand_E(bool* inputVector, unsigned char* EBitSelection, bool* outputVector)
{
unsigned char i;
for (i = 0; i < 48; i++)
{
outputVector[i] = inputVector[EBitSelection[i] - 1];
}
}

// primitiveSelection
void primitiveSelection(bool* inputVector, unsigned char S[][4][16], bool* outputVector)
{
int i, j;
unsigned char charTmp, row, col;
bool boolTmp[4] = {0};
for (i = 0; i < 8; i++)
{
    row = inputVector[i * 6] * 2 + inputVector[i * 6 + 5] * 1;
    col = inputVector[i * 6 + 1] * 8 + inputVector[i * 6 + 2] * 4 + inputVector[i * 6 + 3] * 2 + inputVector[i * 6 + 4] * 1;
    charTmp = S[i][row][col];
    char2Bool(charTmp, boolTmp, 4);
    for (j = 0; j < 4; j++)
        {
            outputVector[i * 4 + j] = boolTmp[j];
        }
}
}

//cipherFunction
void cipherFunction(bool* mR, bool* Key, unsigned char* EBitSelection, unsigned char S[][4][16], unsigned char* P, bool* FOutput)
{
bool EmR[48] = {0}, KEmR[48] = {0}, SmR[32] = {0}, PmR[32] = {0};
expand_E(mR, EBitSelection, EmR);
XOR(Key, EmR, 48, KEmR);
primitiveSelection(KEmR, S, SmR);
permute_P(SmR, P, PmR);
memcpy(FOutput, PmR, 32 * sizeof(PmR[0]));
}

//separate_RL
void separate_RL(bool* vector, unsigned char length, bool* keyR, bool* keyL)
{
int i;
for (i = 0; i < ( length / 2 ); i++)
{
keyL[i] = vector[i];
keyR[i] = vector[i + (length / 2)];
}
}

//join_RL
void join_RL(bool* vector, unsigned char length, bool* keyR, bool* keyL)
{
int i;
for (i = 0; i < ( length / 2 ); i++)
{
vector[i] = keyL[i];
vector[i + (length / 2)] = keyR[i];
}
}

//printVector
void printVector(bool* ip, unsigned char length)
{
int i;
for (i = 0; i < length; i++)
{
    printf("%d", *(ip+i));
    
}
}

//shift_Left
void shift_Left(bool* inputVector, unsigned char nShifts, bool* outputVector)
{
unsigned char shiftCntr, bitCntr, nBits = 28;
bool inputVectorTmp[28];
for (bitCntr = 0; bitCntr < nBits; bitCntr++)
{
    inputVectorTmp[bitCntr] = inputVector[bitCntr];
}
for (shiftCntr = 0; shiftCntr < nShifts; shiftCntr++)
{
    outputVector[nBits - 1] = inputVectorTmp[0];
    for (bitCntr = 1; bitCntr < nBits; bitCntr++)
        {
            outputVector[bitCntr - 1] = inputVectorTmp[bitCntr];
        }
    for (bitCntr = 0; bitCntr < nBits; bitCntr++)
    {
        inputVectorTmp[bitCntr] = outputVector[bitCntr];
    }
}
}

//XOR
void XOR(bool* vector1, bool* vector2, unsigned char nElements, bool* vectorRes)
{
int i;
for(i = 0; i < nElements; i++)
    {
    if ( ((vector1[i] == 1) && (vector2[i] == 0)) || ((vector1[i] == 0) && (vector2[i] == 1)) )
        {
            vectorRes[i] = 1;
        }
    else if ( ((vector1[i] == 1) && (vector2[i] == 1)) || ((vector1[i] == 0) && (vector2[i] == 0)) )
        {
            vectorRes[i] = 0;
        }
    }
}

//char2Bool
void char2Bool(unsigned char charVar, bool* boolVec, unsigned char nBits)
{
int i;
for (i = 0; i < nBits; i++)
{
    if ( charVar % 2 == 0)
        {
            boolVec[nBits - i - 1] = 0;
        }
    else{
            boolVec[nBits - i - 1] = 1;
        }
    charVar = (charVar - (charVar % 2)) / 2;
}
}


// Main Function
void main(){

/* The 64 bit plaintext, 64-bit Key and the resulting 
Cipher are defined as 64-element boolean vectors */ 
bool plaintext[64] = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1};
bool Cipher[64];
bool key[64] = {0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1};


// Parameters or Tables defined

unsigned char S[8][4][16] = {
{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
{{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
{{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
{{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
{{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
{{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
{{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
{{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
};

unsigned char PC1[56] = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

unsigned char PC2[48] = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

unsigned char IP_[64]  = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

unsigned char nLeftShift[16]  = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

unsigned char EBitSelection[48] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

unsigned char P[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};

unsigned char IPInv[64] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};

/* The key and plaintext are separated into their right and left sides and permuted in loops. 
The required variables for this process are defined below */

bool keyL[17][28]; // C0, C1 to C16, 17 in total

bool keyR[17][28]; // D0, D1 to D16, 17 in total

bool keyBeforePC2[16][56]; // CnDn, 16 in total

bool keyAfterPC2[16][48]; // Kn, 16 48-bit keys

bool plaintextL[17][32]; // left part of plaintext

bool plaintextR[17][32]; // right part of plaintext

bool EplaintextR[17][48]; // After expanding R

bool KEplaintextR[17][48]; // XOR of expanded R and Key

bool SplaintextR[17][32] = {0}; // After applying primitive S

bool FOutput[32] = {0}; // variable for the output of cipher function F 

bool next_key[56]; // key after PC1

bool PreCrypto[64];


printf(" The plaintext :\n");
printVector(plaintext, 64);

printf("\n \n The Key :\n");
printVector(key, 64);

// Creating a 56 bit key
permutedChoice1(key, PC1, next_key);
printf("\n \n Key Schedule Process :\n");
printf("The Key after PC1 is :\n");
printVector(next_key, 56);

//  the Key is separated into right and left keys
separate_RL(next_key, 56, keyR[0], keyL[0]);
printf("\n The left part of Key after PC1 is (C%d):\n", 0);
printVector(keyL[0], 28);
printf("\n The right part of Key after PC1 is (D%d):\n", 0);
printVector(keyR[0], 28);


// shift according to nLeftShift in a loop to get 16 56-bit keys, called keyBeforePC2
unsigned char i;
for (i = 1; i <= 16; i++)
{
    shift_Left(keyR[i - 1], nLeftShift[i - 1], keyR[i]);
    shift_Left(keyL[i - 1], nLeftShift[i - 1], keyL[i]);
    join_RL(keyBeforePC2[i - 1], 56, keyR[i], keyL[i]);
    printf("\n The left part of K%d is (C%d):\t \n", i, i);
    printVector(keyL[i], 28);
    printf("\n The right part of K%d is (D%d):\t \n", i, i);
    printVector(keyR[i], 28);
}

// The keys are permuted by PC2, resulting in the final keys for decryption
for (i = 0; i < 16; i++)
{
    permutedChoice2(keyBeforePC2[i], PC2, keyAfterPC2[i]);
    printf("\n The K%d after PC2 is (48 bits):\n", i+1);
    printVector(keyAfterPC2[i], 48);
}


// Encrypt each 64-bit of data starting with initial permutation
printf("\n \n The Encryption Process :\t \n");
initialPermutation(plaintext, IP_, plaintextR[0], plaintextL[0]);
printf("The left part of plaintext after Initial Permutation is (L%d):\t \n", 0);
printVector(plaintextL[0], 32);
printf("\n The right part of plaintext after Initial Permutation is (R%d):\t \n", 0);
printVector(plaintextR[0], 32);

// The plaintext modification loop
for (i = 1; i <= 17; i++)
{
    memcpy(plaintextL[i], plaintextR[i - 1], 32* sizeof(plaintextR[i][0]));
    cipherFunction(plaintextR[i - 1], keyAfterPC2[i - 1], EBitSelection, S, P, FOutput);
    XOR(plaintextL[i-1], FOutput, 32, plaintextR[i]);
}
printf("\n The left part of cipher after encryption is (L%d): \n", 16);
printVector(plaintextL[16],32);
printf("\n The right part of cipher after encryption is (R%d): \n", 16);
printVector(plaintextR[16],32);

for(int i=0; i<32; i++){
PreCrypto[i] = plaintextR[16][i];
PreCrypto[i+32] = plaintextL[16][i];
}

printf("\n Cipher before Inverse Initial Permutation is (64 bits): \n");
printVector(PreCrypto, 64);
    
inversePermutation(PreCrypto, IPInv, Cipher);
printf("\n The final encrypted cipher is (64 bits): \n");
printVector(Cipher, 64);

}




