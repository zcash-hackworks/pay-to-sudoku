#include <stdlib.h>
#include <iostream>

#include "snark.hpp"
#include "test.h"
#include "sha256.h"

using namespace libsnark;
using namespace std;

int main()
{
    // Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();
    // Generate the verifying/proving keys. (This is trusted setup!)
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

    // Run test vectors.
    {
        vector<uint8_t> puzzle = 
        {
            8, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3, 6, 0, 0, 0, 0, 0,
            0, 7, 0, 0, 9, 0, 2, 0, 0,
            
            0, 5, 0, 0, 0, 7, 0, 0, 0,
            0, 0, 0, 0, 4, 5, 7, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 3, 0,

            0, 0, 1, 0, 0, 0, 0, 6, 8,
            0, 0, 8, 5, 0, 0, 0, 1, 0,
            0, 9, 0, 0, 0, 0, 4, 0, 0
        };

        vector<uint8_t> solution = 
        {
            8, 1, 2, 7, 5, 3, 6, 4, 9,
            9, 4, 3, 6, 8, 2, 1, 7, 5,
            6, 7, 5, 4, 9, 1, 2, 8, 3,
            
            1, 5, 4, 2, 3, 7, 8, 9, 6,
            3, 6, 9, 8, 4, 5, 7, 2, 1,
            2, 8, 7, 1, 6, 9, 5, 3, 4,

            5, 2, 1, 9, 7, 4, 3, 6, 8,
            4, 3, 8, 5, 2, 6, 9, 1, 7,
            7, 9, 6, 3, 1, 8, 4, 5, 2
        };

        assert(run_test(keypair, puzzle, solution));
    }

    // Run test vectors.
    {
        vector<uint8_t> puzzle = 
        {
            8, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3, 6, 0, 0, 0, 0, 0,
            0, 7, 0, 0, 9, 0, 2, 0, 0,
            
            0, 5, 0, 0, 0, 7, 0, 0, 0,
            0, 0, 0, 0, 4, 5, 7, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 3, 0,

            0, 0, 1, 0, 0, 0, 0, 6, 8,
            0, 0, 8, 5, 0, 0, 0, 1, 0,
            0, 9, 0, 0, 0, 0, 4, 0, 0
        };

        vector<uint8_t> solution = 
        {
            8, 1, 2, 7, 5, 3, 6, 4, 9,
            9, 4, 3, 6, 8, 2, 1, 7, 5,
            6, 7, 5, 4, 9, 1, 2, 8, 3,
            
            1, 5, 4, 2, 3, 7, 8, 9, 6,
            3, 6, 9, 8, 4, 5, 7, 2, 1,
            2, 8, 7, 1, 6, 9, 5, 3, 4,

            5, 2, 1, 9, 7, 4, 3, 6, 8,
            4, 3, 8, 5, 2, 6, 9, 1, 7,
            7, 9, 6, 3, 1, 8, 3, 5, 2 // not a solution to the puzzle, 4 => 3
        };

        assert(!run_test(keypair, puzzle, solution));
    }

    {
        vector<uint8_t> puzzle = 
        {
            8, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3, 6, 0, 0, 0, 0, 0,
            0, 7, 0, 0, 9, 0, 2, 0, 0,
            
            0, 5, 0, 0, 0, 7, 0, 0, 0,
            0, 0, 0, 0, 4, 5, 7, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 3, 0,

            0, 0, 1, 0, 0, 0, 0, 6, 8,
            0, 0, 8, 5, 0, 0, 0, 1, 0,
            0, 9, 0, 0, 0, 0, 4, 0, 0
        };

        vector<uint8_t> solution = 
        {
            8, 1, 2, 7, 5, 3, 6, 4, 8, // invalid! 8 is repeated on both the col and row
            9, 4, 3, 6, 8, 2, 1, 7, 5,
            6, 7, 5, 4, 9, 1, 2, 8, 3,
            
            1, 5, 4, 2, 3, 7, 8, 9, 6,
            3, 6, 9, 8, 4, 5, 7, 2, 1,
            2, 8, 7, 1, 6, 9, 5, 3, 4,

            5, 2, 1, 9, 7, 4, 3, 6, 8,
            4, 3, 8, 5, 2, 6, 9, 1, 7,
            7, 9, 6, 3, 1, 8, 4, 5, 2
        };

        assert(!run_test(keypair, puzzle, solution));
    }

    {
        vector<uint8_t> puzzle = 
        {
            8, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3, 6, 0, 0, 0, 0, 0,
            0, 7, 0, 0, 9, 0, 2, 0, 0,
            
            0, 5, 0, 0, 0, 7, 0, 0, 0,
            0, 0, 0, 0, 4, 5, 7, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 3, 0,

            0, 0, 1, 0, 0, 0, 0, 6, 8,
            0, 0, 8, 5, 0, 0, 0, 1, 0,
            0, 9, 0, 0, 0, 0, 4, 0, 0
        };

        vector<uint8_t> solution = 
        {
            8, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 3, 6, 1, 1, 1, 1, 1,
            1, 7, 1, 1, 9, 1, 2, 1, 1,
            
            1, 5, 1, 1, 1, 7, 1, 1, 1,
            1, 1, 1, 1, 4, 5, 7, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 3, 1,

            1, 1, 1, 1, 1, 1, 1, 6, 8,
            1, 1, 8, 5, 1, 1, 1, 1, 1,
            1, 9, 1, 1, 1, 1, 4, 1, 1
        };

        assert(!run_test(keypair, puzzle, solution));
    }
}

bool run_test(r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& keypair,
    std::vector<uint8_t> puzzle,
    std::vector<uint8_t> solution
    ) {

    vector<bool> key = int_list_to_bits({206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95, 134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94}, 8);
    vector<bool> h_of_key = int_list_to_bits({253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164, 65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9}, 8);

    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, puzzle, solution, key, h_of_key);

    if (!proof) {
        return false;
    } else {
        assert(verify_proof(keypair.vk, *proof, puzzle, h_of_key));
        return true;
    }
}
