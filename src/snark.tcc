#include "gadget.hpp"

using namespace std;

std::vector<std::vector<bool>> convertPuzzleToBool(std::vector<uint8_t> puzzle) {
    std::vector<vector<bool>> new_puzzle;

    for(vector<uint8_t>::iterator it = puzzle.begin(); it != puzzle.end(); ++it) {
        new_puzzle.insert(new_puzzle.end(), convertIntToVector(*it));
    }

    return new_puzzle;
}

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair()
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    sodoku_gadget<FieldT> g(pb, 3);
    g.generate_r1cs_constraints();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}

template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                   vector<uint8_t> &puzzle,
                                                                   vector<uint8_t> &solution,
                                                                   vector<unsigned char> &key,
                                                                   vector<unsigned char> &h_of_key
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    sodoku_gadget<FieldT> g(pb, 3);
    g.generate_r1cs_constraints();

    auto new_puzzle = convertPuzzleToBool(puzzle);
    auto new_solution = convertPuzzleToBool(solution);

    vector<bool> new_key(256);
    vector<bool> new_h_of_key(256);

    convertBytesVectorToVector(key, new_key);
    convertBytesVectorToVector(h_of_key, new_h_of_key);

    g.generate_r1cs_witness(new_puzzle, new_solution, new_key, new_h_of_key);

    if (!pb.is_satisfied()) {
        return boost::none;
    }

    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  vector<uint8_t> &puzzle,
                  vector<unsigned char> &h_of_key
                 )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    auto new_puzzle = convertPuzzleToBool(puzzle);

    vector<bool> new_h_of_key(256);
    convertBytesVectorToVector(h_of_key, new_h_of_key);

    const r1cs_primary_input<FieldT> input = sodoku_input_map<FieldT>(3, new_puzzle, new_h_of_key);

    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}