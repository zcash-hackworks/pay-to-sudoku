#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "algebra/fields/field_utils.hpp"

using namespace libsnark;

template<typename FieldT>
class l_gadget : public gadget<FieldT> {
public:
    unsigned int dimension; /* N */

    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

    std::vector<pb_variable_array<FieldT>> puzzle_values;
    std::vector<pb_variable_array<FieldT>> solution_values;


    l_gadget(protoboard<FieldT> &pb, unsigned int n);
    void generate_r1cs_constraints();
    void generate_r1cs_witness(std::vector<bit_vector> &puzzle_values,
                               std::vector<bit_vector> &input_solution_values);
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(std::vector<bit_vector> &puzzle_values);

#include "gadget.tcc"
