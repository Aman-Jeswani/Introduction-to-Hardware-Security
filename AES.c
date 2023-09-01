/*
https://cboard.cprogramming.com/c-programming/87805-[tutorial]-implementing-advanced-encryption-standard.html
*/
#include <stdio.h>
#include <stdlib.h>


enum keySize
{
    SIZE_16 = 16
};

void core(unsigned char *word, int iteration);
void rotate(unsigned char *word);
void subBytes(unsigned char *state);
void shiftRows(unsigned char *state);
void shiftRow(unsigned char *state, unsigned char nbr);
void expandKey(unsigned char *expandedKey, unsigned char *key, enum keySize, size_t expandedKeySize);


char aes_encrypt(unsigned char *input, unsigned char *output, unsigned char *key, enum keySize size);
void addRoundKey(unsigned char *state, unsigned char *roundKey);
void mixColumns(unsigned char *state);
void mixColumn(unsigned char *column);
void aes_round(unsigned char *state, unsigned char *roundKey);
void createRoundKey(unsigned char *expandedKey, unsigned char *roundKey);
void aes_main(unsigned char *state, unsigned char *expandedKey, int nbrRounds);
unsigned char multiply_in_gf8(unsigned char a, unsigned char b);


char aes_decrypt(unsigned char *input, unsigned char *output, unsigned char *key, enum keySize size);
void invSubBytes(unsigned char *state);
void invShiftRows(unsigned char *state);
void invShiftRow(unsigned char *state, unsigned char nbr);
void invMixColumns(unsigned char *state);
void invMixColumn(unsigned char *column);
void aes_invRound(unsigned char *state, unsigned char *roundKey);
void aes_invMain(unsigned char *state, unsigned char *expandedKey, int nbrRounds);


#define UNKNOWN_KEYSIZE 11
#define MEMORY_ALLOCATION_PROBLEM 33

// The round constant word array
unsigned char Rcon[255] = {

    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb

    };


unsigned char SBOX[256] = {

    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

    };


unsigned char ReverseSBOX[256] = {

    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d

    };


// Used to shift the 4 byte word left cyclically
void rotate(unsigned char *input)
{
    unsigned char temp;
    int index;

    temp = input[0]; // Store the first element in a temporary variable

    for (index = 0; index < 3; index++)
        input[index] = input[index + 1]; // Shift elements to the left

    input[3] = temp; // Place the first element at the end
}


// Applying Key Schedule
void core(unsigned char *inputWord, int iteration)
{
    int i;

    rotate(inputWord); // Rotate the input word

    for (i = 0; i < 4; ++i)
    {
        inputWord[i] = SBOX[inputWord[i]]; // Apply S-box substitution to each byte of the word
    }

    inputWord[0] = inputWord[0] ^ Rcon[iteration]; // XOR the first byte of the word with a round constant value
}


// Key expansion
void expandKey(unsigned char *outputExpandedKey,
               unsigned char *inputKey,
               enum keySize inputSize,
               size_t outputExpandedKeySize)
{
    int currentSize = 0;   // Current size of the expanded key
    int rconIteration = 1; // Rcon iteration value
    int i;
    unsigned char t[4] = {0}; // Temporary storage for a 4-byte word

    // Copy the input key to the expanded key
    for (i = 0; i < inputSize; i++)
        outputExpandedKey[i] = inputKey[i];
    currentSize += inputSize;

    // Generate additional key bytes until the expanded key reaches the desired size
    while (currentSize < outputExpandedKeySize)
    {
        // Take the last 4-byte word from the expanded key
        for (i = 0; i < 4; i++)
        {
            t[i] = outputExpandedKey[(currentSize - 4) + i];
        }
        // Perform core operation on the temporary word every inputSize bytes
        if (currentSize % inputSize == 0)
        {
            core(t, rconIteration++);
        }
        // Generate the next 4-byte word and XOR with the corresponding word from the previous inputSize bytes
        for (i = 0; i < 4; i++)
        {
            outputExpandedKey[currentSize] = outputExpandedKey[currentSize - inputSize] ^ t[i];
            currentSize++;
        }
    }
}


void subBytes(unsigned char *inputState)
{
    int index;

    for (index = 0; index < 16; index++)
        inputState[index] = SBOX[inputState[index]]; // Apply S-box substitution to each byte of the input state
}


void shiftRows(unsigned char *inputState)
{
    int row;

    for (row = 0; row < 4; row++)
        shiftRow(inputState + row * 4, row); // Shift each row of the input state
}


void shiftRow(unsigned char *inputState, unsigned char number)
{
    int row, col;
    unsigned char temp;

    for (row = 0; row < number; row++)
    {
        temp = inputState[0]; // Store the first element in a temporary variable

        for (col = 0; col < 3; col++)
            inputState[col] = inputState[col + 1]; // Shift elements to the left within the row

        inputState[3] = temp; // Place the first element at the end of the row
    }
}


void addRoundKey(unsigned char *inputState, unsigned char *inputRoundKey)
{
    int i;

    for (i = 0; i < 16; i++)
        inputState[i] = inputState[i] ^ inputRoundKey[i]; // XOR each byte of the input state with the corresponding byte of the round key
}


unsigned char multiply_in_gf8(unsigned char operandA, unsigned char operandB)
{
    unsigned char product = 0;
    unsigned char counter;
    unsigned char highBitSet;

    // Perform Galois Field multiplication for 8 iterations
    for (counter = 0; counter < 8; counter++)
    {
        // Check if the least significant bit of operandB is 1
        if ((operandB & 1) == 1)
            product ^= operandA; // XOR the product with operandA if the LSB of operandB is 1

        highBitSet = (operandA & 0x80); // Check if the high bit of operandA is set
        operandA <<= 1; // Left shift operandA by 1 bit

        // If the high bit of operandA was set, perform an XOR operation with 0x1b (a predefined irreducible polynomial)
        if (highBitSet == 0x80)
            operandA ^= 0x1b;

        operandB >>= 1; // Right shift operandB by 1 bit
    }

    return product; // Return the resulting product
}


void mixColumns(unsigned char *inputState)
{
    int i, j;
    unsigned char inputColumn[4];

    // Process each column of the input state
    for (i = 0; i < 4; i++)
    {
        // Extract the column values into the inputColumn array
        for (j = 0; j < 4; j++)
        {
            inputColumn[j] = inputState[(j * 4) + i]; // Extract the j-th byte from the i-th column
        }
        // Perform the MixColumn transformation on the inputColumn
        mixColumn(inputColumn);
        // Update the input state with the modified column values
        for (j = 0; j < 4; j++)
        {
            inputState[(j * 4) + i] = inputColumn[j]; // Update the j-th byte of the i-th column with the modified value
        }
    }
}


void mixColumn(unsigned char *inputColumn)
{
    unsigned char copy[4];
    int i;

    // Make a copy of the input column
    for (i = 0; i < 4; i++)
    {
        copy[i] = inputColumn[i];
    }

    // Perform the mixing operations on the input column
    inputColumn[0] = multiply_in_gf8(copy[0], 2) ^
                     multiply_in_gf8(copy[3], 1) ^
                     multiply_in_gf8(copy[2], 1) ^
                     multiply_in_gf8(copy[1], 3);

    inputColumn[1] = multiply_in_gf8(copy[1], 2) ^
                     multiply_in_gf8(copy[0], 1) ^
                     multiply_in_gf8(copy[3], 1) ^
                     multiply_in_gf8(copy[2], 3);

    inputColumn[2] = multiply_in_gf8(copy[2], 2) ^
                     multiply_in_gf8(copy[1], 1) ^
                     multiply_in_gf8(copy[0], 1) ^
                     multiply_in_gf8(copy[3], 3);

    inputColumn[3] = multiply_in_gf8(copy[3], 2) ^
                     multiply_in_gf8(copy[2], 1) ^
                     multiply_in_gf8(copy[1], 1) ^
                     multiply_in_gf8(copy[0], 3);
}


void aes_round(unsigned char *inputState, unsigned char *inputRoundKey)
{
    // Perform AES round operations on the input state
    subBytes(inputState);
    shiftRows(inputState);
    mixColumns(inputState);
    addRoundKey(inputState, inputRoundKey);
}


void createRoundKey(unsigned char *inputExpandedKey, unsigned char *outputRoundKey)
{
    int column, row;
    // Create the round key from the expanded key
    for (column = 0; column < 4; column++)
    {
        for (row = 0; row < 4; row++)
        {
            // Copy the bytes from the expanded key to the round key
            outputRoundKey[(column + (row * 4))] = inputExpandedKey[(column * 4) + row];
        }
    }
}


void aes_main(unsigned char *inputState, unsigned char *inputExpandedKey, int inputNbrRounds)
{
    int i = 0;
    unsigned char roundKey[16];

    // Initialize the round key with the first 16 bytes of the expanded key
    createRoundKey(inputExpandedKey, roundKey);
    addRoundKey(inputState, roundKey);
    // Perform AES rounds
    for (i = 1; i < inputNbrRounds; i++)
    {
        // Generate the round key for the current round
        createRoundKey(inputExpandedKey + 16 * i, roundKey);

        // Perform AES round operation on the input state with the round key
        aes_round(inputState, roundKey);
    }
    // Generate the final round key for the last round
    createRoundKey(inputExpandedKey + 16 * inputNbrRounds, roundKey);
    // Perform the final AES operations on the input state
    subBytes(inputState);
    shiftRows(inputState);
    addRoundKey(inputState, roundKey);
}


char aes_encrypt(unsigned char *inputData,
                 unsigned char *outputData,
                 unsigned char *encryptionKey,
                 enum keySize keySize)
{
    int expandedKeySize;
    int numberOfRounds;
    unsigned char *expandedEncryptionKey;
    unsigned char block[16];
    int i, j;

    // Determine the number of rounds based on the key size
    switch (keySize)
    {
    case 16:
        numberOfRounds = 10;
        break;
    default:
        return UNKNOWN_KEYSIZE; // Return error for unknown key size
        break;
    }

    // Calculate the size of the expanded key
    expandedKeySize = (16 * (numberOfRounds + 1));

    // Allocate memory for the expanded key
    if ((expandedEncryptionKey = malloc(expandedKeySize * sizeof(char))) == NULL)
    {
        return MEMORY_ALLOCATION_PROBLEM; // Return error if memory allocation fails
    }

    // Copy the input data into the block array
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            block[(i + (j * 4))] = inputData[(i * 4) + j];
    }
    // Expand the encryption key into the expanded key
    expandKey(expandedEncryptionKey, encryptionKey, keySize, expandedKeySize);
    // Perform AES encryption on the block using the expanded key
    aes_main(block, expandedEncryptionKey, numberOfRounds);
    // Copy the encrypted block into the output data array
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            outputData[(i * 4) + j] = block[(i + (j * 4))];
    }
    return 0; // Return success
}


void invSubBytes(unsigned char *inputState)
{
    int i;
    // Apply inverse S-box substitution to each byte of the input state
    for (i = 0; i < 16; i++)
        inputState[i] = ReverseSBOX[inputState[i]];
}


void invShiftRows(unsigned char *inputState)
{
    int row;
    // Perform inverse shifting of rows in the input state
    for (row = 0; row < 4; row++)
        invShiftRow(inputState + row * 4, row);
}


void invShiftRow(unsigned char *inputState, unsigned char numShifts)
{
    int i, j;
    unsigned char temp;

    // Perform inverse shifting of bytes within a row
    for (i = 0; i < numShifts; i++)
    {
        // Store the last byte of the row in a temporary variable
        temp = inputState[3];
        // Shift the bytes within the row to the right
        for (j = 3; j > 0; j--)
            inputState[j] = inputState[j - 1];
        // Assign the stored byte to the first position of the row
        inputState[0] = temp;
    }
}


void invMixColumns(unsigned char *inputState)
{
    int columnIdx, rowIdx;
    unsigned char column[4];

    // Perform inverse MixColumns operation on each column of the state
    for (columnIdx = 0; columnIdx < 4; columnIdx++)
    {
        // Extract a column from the state into the 'column' array
        for (rowIdx = 0; rowIdx < 4; rowIdx++)
        {
            column[rowIdx] = inputState[(rowIdx * 4) + columnIdx];
        }

        // Apply the inverse MixColumn transformation to the column
        invMixColumn(column);
        // Update the state with the transformed column
        for (rowIdx = 0; rowIdx < 4; rowIdx++)
        {
            inputState[(rowIdx * 4) + columnIdx] = column[rowIdx];
        }
    }
}


void invMixColumn(unsigned char *inputColumn)
{
    unsigned char cpy[4];
    int i;

    // Making a copy of the input column
    for (i = 0; i < 4; i++)
    {
        cpy[i] = inputColumn[i];
    }

    // Performing the inverse MixColumn transformation on the column
    inputColumn[0] = multiply_in_gf8(cpy[0], 14) ^
                     multiply_in_gf8(cpy[3], 9) ^
                     multiply_in_gf8(cpy[2], 13) ^
                     multiply_in_gf8(cpy[1], 11);

    inputColumn[1] = multiply_in_gf8(cpy[1], 14) ^
                     multiply_in_gf8(cpy[0], 9) ^
                     multiply_in_gf8(cpy[3], 13) ^
                     multiply_in_gf8(cpy[2], 11);

    inputColumn[2] = multiply_in_gf8(cpy[2], 14) ^
                     multiply_in_gf8(cpy[1], 9) ^
                     multiply_in_gf8(cpy[0], 13) ^
                     multiply_in_gf8(cpy[3], 11);

    inputColumn[3] = multiply_in_gf8(cpy[3], 14) ^
                     multiply_in_gf8(cpy[2], 9) ^
                     multiply_in_gf8(cpy[1], 13) ^
                     multiply_in_gf8(cpy[0], 11);
}


void aes_invRound(unsigned char *inputState, unsigned char *inputRoundKey)
{
    invShiftRows(inputState);
    invSubBytes(inputState);
    addRoundKey(inputState, inputRoundKey);
    invMixColumns(inputState);
}


void aes_invMain(unsigned char *inputState, unsigned char *inputExpandedKey, int numberOfRounds)
{
    int i = 0;
    unsigned char roundKey[16];

    // Generating the last round key
    createRoundKey(inputExpandedKey + 16 * numberOfRounds, roundKey);
    // Applying AddRoundKey transformation with the last round key
    addRoundKey(inputState, roundKey);

    // Iterating through the remaining rounds in reverse order
    for (i = numberOfRounds - 1; i > 0; i--)
    {
        // Generating the round key for the current round
        createRoundKey(inputExpandedKey + 16 * i, roundKey);
        // Applying inverse round transformation
        aes_invRound(inputState, roundKey);
    }

    createRoundKey(inputExpandedKey, roundKey);
    invShiftRows(inputState);
    invSubBytes(inputState);
    addRoundKey(inputState, roundKey);
}


char aes_decrypt(unsigned char *inputData,
                 unsigned char *outputData,
                 unsigned char *encryptionKey,
                 enum keySize keySize)
{
    int expandedKeySize;
    int numRounds;
    unsigned char *expandedKey;
    unsigned char block[16];
    int i, j;

    switch (keySize)
    {
    case 16:
        numRounds = 10;
        break;
    default:
        return UNKNOWN_KEYSIZE;
        break;
    }

    expandedKeySize = (16 * (numRounds + 1));
    if ((expandedKey = malloc(expandedKeySize * sizeof(char))) == NULL)
    {
        return MEMORY_ALLOCATION_PROBLEM;
    }

    // Copy the input data to the block array
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            block[(i + (j * 4))] = inputData[(i * 4) + j];
    }

    // Expand the encryption key
    expandKey(expandedKey, encryptionKey, keySize, expandedKeySize);
    // Apply inverse AES transformation to the block
    aes_invMain(block, expandedKey, numRounds);
    // Copy the transformed block to the output data array
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            outputData[(i * 4) + j] = block[(i + (j * 4))];
    }
    return 0;
}


int main(int argc, char *argv[])
{
    unsigned char expandedKey[176];
    unsigned char aesKey[16] = {'A', 'E', 'S', 'K', 'E', 'Y', '-', '-', '-', '-', 'A', 'E', 'S', 'K', 'E', 'Y'};
    enum keySize size = SIZE_16;
    unsigned char plaintext[16] = {'I', '-', 'a', 'm', '-', 't', 'h', 'e', '-', 'S', 'e', 'n', 'a', 't', 'e', '.'};
    unsigned char ciphertext[16];
    unsigned char decryptedtext[16];
    int i;

    printf("Implementation of AES\n");

    printf("\nKey:\n");
    for (i = 0; i < 16; i++)
    {
        printf("%c", aesKey[i], ((i + 1) % 16) ? ' ' : '\n');
    }

    // Key expansion
    expandKey(expandedKey, aesKey, size, 176);

    printf("\nPlain text:\n");
    for (i = 0; i < 16; i++)
    {
        printf("%c", plaintext[i]);
    }

    // AES encryption
    aes_encrypt(plaintext, ciphertext, aesKey, 16);

    printf("\nCipher text:\n");
    for (i = 0; i < 16; i++)
    {
        printf("%c", ciphertext[i]);
    }

    printf("\nCipher text in hexadecimal:\n");
    for (i = 0; i < 16; i++)
    {
        printf("%2.2x%c", ciphertext[i], ' ');
    }

    // AES decryption
    aes_decrypt(ciphertext, decryptedtext, aesKey, 16);

    printf("\nDecrypted text:\n");
    for (i = 0; i < 16; i++)
    {
        printf("%c", decryptedtext[i]);
    }

    return 0;
}
