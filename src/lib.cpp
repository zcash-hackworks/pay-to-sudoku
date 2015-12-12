#include <stdlib.h>
#include "snark.hpp"

typedef void (*keypair_callback)(void*, const char*, int32_t, const char*, int32_t);
typedef void (*proof_callback)(void*, uint32_t, const uint8_t*, const char*, int32_t);

extern "C" void decrypt_solution(uint32_t n, uint8_t *enc, unsigned char* key) {
    uint32_t cells = n*n*n*n;

    std::vector<unsigned char> key_bv(key, key+32);
    std::vector<bool> key_v;
    convertBytesVectorToVector(key_bv, key_v);

    std::vector<uint8_t> enc_solution(enc, enc+(n*n*n*n));
    auto enc_solution_bool = convertPuzzleToBool(enc_solution);

    auto dec_solution_bool = xorSolution(enc_solution_bool, key_v);
    auto dec_solution = convertBoolToPuzzle(dec_solution_bool);

    for (uint32_t i = 0; i < cells; i++) {
        enc[i] = dec_solution[i];
    }
}

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

extern "C" bool gen_proof(void *keypair, void* h, proof_callback cb, uint32_t n, uint8_t* puzzle, uint8_t* solution, uint8_t* input_key, uint8_t* input_h_of_key) {
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

        auto encrypted_solution_formatted = convertBoolToPuzzle(encrypted_solution);
        std::string proof_serialized;
        {
            std::stringstream ss;
            ss << actual_proof;
            proof_serialized = ss.str();
        }

        assert(verify_proof(our_keypair->vk, actual_proof, new_puzzle, h_of_key, encrypted_solution));


        // ok
        cb(h, n, &encrypted_solution_formatted[0], proof_serialized.c_str(), proof_serialized.length());

        return true;
    }
}