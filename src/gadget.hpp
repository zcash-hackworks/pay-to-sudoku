#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "algebra/fields/field_utils.hpp"

using namespace libsnark;

template<typename FieldT>
class sodoku_encryption_key : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> seed_key; // 256 bit key
    unsigned int dimension;

    std::vector<std::shared_ptr<digest_variable<FieldT>>> key; // dimension*dimension*8 bit key

    sodoku_encryption_key(protoboard<FieldT> &pb,
                       unsigned int dimension,
                       pb_variable_array<FieldT> &seed_key
                       );
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class sodoku_cell_gadget : public gadget<FieldT> {
public:
    pb_linear_combination<FieldT> number;
    unsigned int dimension;

    /*
        This is an array of bits which indicates whether this
        cell is a particular number in the dimension. It is
        the size of the dimension N^2 of the puzzle. Only one
        bit is set.
    */
    pb_variable_array<FieldT> flags;

    sodoku_cell_gadget(protoboard<FieldT> &pb,
                       unsigned int dimension,
                       pb_linear_combination<FieldT> &number
                       );
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class sodoku_closure_gadget : public gadget<FieldT> {
public:
    unsigned int dimension;

    /*
        This is an array of bits which indicates whether this
        cell is a particular number in the dimension. It is
        the size of the dimension N^2 of the puzzle. Only one
        bit is set.
    */
    std::vector<pb_variable_array<FieldT>> flags;

    sodoku_closure_gadget(protoboard<FieldT> &pb,
                          unsigned int dimension,
                          std::vector<pb_variable_array<FieldT>> &flags
                         );
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class sodoku_gadget : public gadget<FieldT> {
public:
    unsigned int dimension;

    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

    std::vector<pb_variable_array<FieldT>> puzzle_values;
    std::vector<pb_variable_array<FieldT>> solution_values;

    std::vector<pb_linear_combination<FieldT>> puzzle_numbers;
    std::vector<pb_linear_combination<FieldT>> solution_numbers;

    std::vector<std::shared_ptr<sodoku_cell_gadget<FieldT>>> cells;

    std::vector<std::shared_ptr<sodoku_closure_gadget<FieldT>>> closure_rows;
    std::vector<std::shared_ptr<sodoku_closure_gadget<FieldT>>> closure_cols;
    std::vector<std::shared_ptr<sodoku_closure_gadget<FieldT>>> closure_groups;

    std::shared_ptr<digest_variable<FieldT>> seed_key;
    std::shared_ptr<sodoku_encryption_key<FieldT>> key;

    pb_variable_array<FieldT> puzzle_enforce;


    sodoku_gadget(protoboard<FieldT> &pb, unsigned int n);
    void generate_r1cs_constraints();
    void generate_r1cs_witness(std::vector<bit_vector> &puzzle_values,
                               std::vector<bit_vector> &input_solution_values);
};

template<typename FieldT>
r1cs_primary_input<FieldT> sodoku_input_map(std::vector<bit_vector> &puzzle_values);

#include "gadget.tcc"
