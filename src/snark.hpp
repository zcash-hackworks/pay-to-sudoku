#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/common/utils.hpp"
#include <boost/optional.hpp>

using namespace libsnark;

std::vector<bool> convertIntToVector(uint8_t val) {
  std::vector<bool> ret;

  for(unsigned int i = 0; i < sizeof(val) * 8; ++i, val >>= 1) {
    ret.push_back(val & 0x01);
  }

  reverse(ret.begin(), ret.end());
  return ret;
}

void convertBytesVectorToBytes(const std::vector<unsigned char>& v, unsigned char* bytes) {
    for(size_t i = 0; i < v.size(); i++) {
        bytes[i] = v.at(i);
    }
}

void convertBytesToVector(const unsigned char* bytes, std::vector<bool>& v) {
    int numBytes = v.size() / 8;
    unsigned char c;
    for(int i = 0; i < numBytes; i++) {
        c = bytes[i];

        for(int j = 0; j < 8; j++) {
            v.at((i*8)+j) = ((c >> (7-j)) & 1);
        }
    }
}

void convertBytesVectorToVector(const std::vector<unsigned char>& bytes, std::vector<bool>& v) {
      v.resize(bytes.size() * 8);
    unsigned char bytesArr[bytes.size()];
    convertBytesVectorToBytes(bytes, bytesArr);
    convertBytesToVector(bytesArr, v);
}

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair();

template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                   std::vector<uint8_t> &puzzle,
                                                                   std::vector<uint8_t> &solution,
                                                                   std::vector<unsigned char> &key
                                                                   );

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  std::vector<uint8_t> &puzzle
                 );

#include "snark.tcc"
