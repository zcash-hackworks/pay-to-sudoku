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
    assert(run_test(keypair));
}

bool run_test(r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& keypair
    ) {
    vector<uint8_t> v(81, 0);

    cout << "Trying to generate proof..." << endl;
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, v);
    cout << "Proof generated!" << endl;

    if (!proof) {
        return false;
    } else {
        assert(verify_proof(keypair.vk, *proof, v));
        return true;
    }
}
