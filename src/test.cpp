#include <stdlib.h>
#include <iostream>

#include "snark.hpp"
#include "test.h"

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
}

bool run_test(r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& keypair,
    std::vector<uint8_t> puzzle,
    std::vector<uint8_t> solution
    ) {
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, puzzle, solution);

    if (!proof) {
        return false;
    } else {
        assert(verify_proof(keypair.vk, *proof, puzzle));
        return true;
    }
}
