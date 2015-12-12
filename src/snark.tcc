#include "gadget.hpp"
#include "sha256.h"

using namespace std;

std::vector<std::vector<bool>> convertPuzzleToBool(std::vector<uint8_t> puzzle) {
    std::vector<vector<bool>> new_puzzle;

    for(vector<uint8_t>::iterator it = puzzle.begin(); it != puzzle.end(); ++it) {
        new_puzzle.insert(new_puzzle.end(), convertIntToVector(*it));
    }

    return new_puzzle;
}

std::vector<uint8_t> convertBoolToPuzzle(std::vector<std::vector<bool>> bool_puzzle)
{
  std::vector<uint8_t> new_puzzle;

  for(std::vector<std::vector<bool>>::iterator it = bool_puzzle.begin(); it != bool_puzzle.end(); ++it)
  {
    new_puzzle.insert(new_puzzle.end(), convertVectorToInt(*it));
  }

  return new_puzzle;
}

std::vector<std::vector<bool>> xorSolution(const std::vector<std::vector<bool>> &solution, const std::vector<bool> &key)
{
    // input key is 256 bits
    assert(key.size() == 256);

    // this is the final key after PRNG
    std::vector<bool> extended_key;

    // the input key is cropped for 248 bits of security
    // we place an 8 bit counter directly after
    std::vector<bool> cropped_key(key.begin(), key.begin() + (256-8));

    unsigned int i = 0;
    while (extended_key.size() < (solution.size() * 8)) {
      // construct the final key after adding the counter or "salt"
      std::vector<bool> finished_key(cropped_key);
      // construct the salt
      std::vector<bool> salt = convertIntToVector(i);
      assert(salt.size() == 8);
      finished_key.insert(finished_key.end(), salt.begin(), salt.end());

      // finished block minus length padding (added by sha256)
      assert(finished_key.size() == 256);

      // convert it into a plaintext that sha256 likes
      unsigned char finished_key_plaintext[32];
      convertVectorToBytes(finished_key, finished_key_plaintext);

      // "blob" of randomness from this makeshift PRNG
      unsigned char blob[32];

      SHA256_CTX ctx;
      sha256_init(&ctx);
      sha256_update(&ctx, finished_key_plaintext, 32);
      sha256_final(&ctx, blob);

      // convert blob into bool vector
      std::vector<bool> blob_bool(256);
      convertBytesToVector(blob, blob_bool);

      // insert blob into our randomness pool or "extended key" for the cipher
      extended_key.insert(extended_key.end(), blob_bool.begin(), blob_bool.end());

      i++;
    }

    std::vector<std::vector<bool>> result;

    unsigned int j = 0;
    for(std::vector<std::vector<bool>>::const_iterator it = solution.begin(); it != solution.end(); ++it)
    {
      std::vector<bool> intermediate_result;
      for(std::vector<bool>::const_iterator it2 = it->begin(); it2 != it->end(); ++it2) {
        // xor!
        intermediate_result.push_back((!(*it2) != !(extended_key[j])));
        j++;
      }

      result.push_back(intermediate_result);
    }

    return result;
}

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair(uint32_t n)
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    sodoku_gadget<FieldT> g(pb, n);
    g.generate_r1cs_constraints();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}

template<typename ppzksnark_ppT>
boost::optional<std::tuple<r1cs_ppzksnark_proof<ppzksnark_ppT>,std::vector<std::vector<bool>>>>
  generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                 vector<uint8_t> &puzzle,
                 vector<uint8_t> &solution,
                 vector<bool> &key,
                 vector<bool> &h_of_key
                 )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    sodoku_gadget<FieldT> g(pb, 3);
    g.generate_r1cs_constraints();

    auto new_puzzle = convertPuzzleToBool(puzzle);
    auto new_solution = convertPuzzleToBool(solution);
    auto encrypted_solution = xorSolution(new_solution, key);

    g.generate_r1cs_witness(new_puzzle, new_solution, key, h_of_key, encrypted_solution);

    if (!pb.is_satisfied()) {
        return boost::none;
    }

    return std::make_tuple(
      r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input()),
      encrypted_solution
    );
}

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  vector<uint8_t> &puzzle,
                  vector<bool> &h_of_key,
                  std::vector<std::vector<bool>> &encrypted_solution
                 )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    auto new_puzzle = convertPuzzleToBool(puzzle);

    const r1cs_primary_input<FieldT> input = sodoku_input_map<FieldT>(3, new_puzzle, h_of_key, encrypted_solution);

    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}