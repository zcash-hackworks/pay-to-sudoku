#include <stdlib.h>
#include "snark.hpp"

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
        auto actual_proof = std::get<0>(*proof);
        auto encrypted_solution = std::get<1>(*proof);

        assert(verify_proof(keypair.vk, actual_proof, puzzle, h_of_key, encrypted_solution));
        return true;
    }
}

typedef void (*keypair_callback)(void*, const char*, int32_t, const char*, int32_t);

extern "C" void mysnark_init_public_params() {
    default_r1cs_ppzksnark_pp::init_public_params();
}

extern "C" void gen_keypair(uint32_t n, void* h, keypair_callback cb) {
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>(n);

    std::stringstream provingKey;
    provingKey << keypair.pk;
    std::string pk = provingKey.str();

    std::stringstream verifyingKey;
    verifyingKey << keypair.vk;
    std::string vk = verifyingKey.str();

    cb(h, pk.c_str(), pk.length(), vk.c_str(), vk.length());
}

extern "C" void* load_keypair(const char* pk_s, int32_t pk_l, const char* vk_s, int32_t vk_l) {
    r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pk;
    r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk;

    {
        std::stringstream ssProving;
        ssProving.write(pk_s, pk_l);

        ssProving.rdbuf()->pubseekpos(0, std::ios_base::in);
        ssProving >> pk;
    }

    {
        std::stringstream ssProving;
        ssProving.write(vk_s, vk_l);

        ssProving.rdbuf()->pubseekpos(0, std::ios_base::in);
        ssProving >> vk;
    }

    return reinterpret_cast<void*>(new r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>(std::move(pk), std::move(vk)));
}

extern "C" bool gen_proof(void *keypair, uint32_t n, uint8_t* puzzle, uint8_t* solution, uint8_t* input_key, uint8_t* input_h_of_key) {
    auto our_keypair = reinterpret_cast<r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>*>(keypair);

    vector<uint8_t> new_puzzle(puzzle, puzzle+(n*n*n*n));
    vector<uint8_t> new_solution(solution, solution+(n*n*n*n));

    vector<unsigned char> v_input_key(input_key, input_key+32);
    vector<unsigned char> v_input_h_of_key(input_h_of_key, input_h_of_key+32);

    vector<bool> key;
    vector<bool> h_of_key;

    convertBytesVectorToVector(v_input_key, key);
    convertBytesVectorToVector(v_input_h_of_key, h_of_key);
    
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(our_keypair->pk, new_puzzle, new_solution, key, h_of_key);

    if (!proof) {
        return false;
    } else {
        auto actual_proof = std::get<0>(*proof);
        auto encrypted_solution = std::get<1>(*proof);

        assert(verify_proof(our_keypair->vk, actual_proof, new_puzzle, h_of_key, encrypted_solution));
        return true;
    }
}