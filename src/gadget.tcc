template<typename FieldT>
l_gadget<FieldT>::l_gadget(protoboard<FieldT> &pb, unsigned int n) :
        gadget<FieldT>(pb, FMT(annotation_prefix, " l_gadget"))
{
    dimension = n;

    const size_t input_size_in_bits = n * n * 8;
    {
        const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
        input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
        this->pb.set_input_sizes(input_size_in_field_elements);
    }

    puzzle_enforce.allocate(pb, n*n, "puzzle solution subset enforcement");

    puzzle_values.resize(n*n);
    solution_values.resize(n*n);

    for (unsigned int i = 0; i < (n*n); i++) {
        puzzle_values[i].allocate(pb, 8, "puzzle_values[i]");
        solution_values[i].allocate(pb, 8, "solution_values[i]");
        input_as_bits.insert(input_as_bits.end(), puzzle_values[i].begin(), puzzle_values[i].end());
    }

    assert(input_as_bits.size() == input_size_in_bits);
    unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));
}

template<typename FieldT>
void l_gadget<FieldT>::generate_r1cs_constraints()
{
    std::vector<linear_combination<FieldT>> puzzle_numbers;
    std::vector<linear_combination<FieldT>> solution_numbers;

    for (unsigned int i = 0; i < (dimension*dimension); i++) {
        for (unsigned int j = 0; j < 8; j++) {
            // ensure bitness
            generate_boolean_r1cs_constraint<FieldT>(this->pb, solution_values[i][j], "solution_bitness");
        }

        puzzle_numbers.push_back(pb_packing_sum<FieldT>(pb_variable_array<FieldT>(puzzle_values[i].rbegin(), puzzle_values[i].rend())));
        solution_numbers.push_back(pb_packing_sum<FieldT>(pb_variable_array<FieldT>(solution_values[i].rbegin(), solution_values[i].rend())));

        // enforce solution is subset of puzzle

        // puzzle_numbers[i] must be 0 or 1
        generate_boolean_r1cs_constraint<FieldT>(this->pb, puzzle_enforce[i], "enforcement bitness");

        // puzzle_numbers[i] must be 1 if the puzzle value is nonzero
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(puzzle_numbers[i], 1 - puzzle_enforce[i], 0), "enforcement");
        
        // solution_numbers[i] must equal puzzle_numbers[i] if puzzle_enforce[i] is 1
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(puzzle_enforce[i], (solution_numbers[i] - puzzle_numbers[i]), 0), "enforcement equality");
    }

    unpack_inputs->generate_r1cs_constraints(true);
}

template<typename FieldT>
void l_gadget<FieldT>::generate_r1cs_witness(std::vector<bit_vector> &input_puzzle_values,
                                             std::vector<bit_vector> &input_solution_values
    )
{
    assert(input_puzzle_values.size() == dimension*dimension);
    assert(input_solution_values.size() == dimension*dimension);
    for (unsigned int i = 0; i < dimension*dimension; i++) {
        assert(input_puzzle_values[i].size() == 8);
        assert(input_solution_values[i].size() == 8);
        puzzle_values[i].fill_with_bits(this->pb, input_puzzle_values[i]);
        solution_values[i].fill_with_bits(this->pb, input_solution_values[i]);

        // if any of the bits of the input puzzle value is nonzero,
        // we must enforce it
        bool enforce = false;
        for (unsigned int j = 0; j < 8; j++) {
            if (input_puzzle_values[i][j]) {
                enforce = true;
                break;
            }
        }

        this->pb.val(puzzle_enforce[i]) = enforce ? FieldT::one() : FieldT::zero();
    }

    unpack_inputs->generate_r1cs_witness_from_bits();
}

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(unsigned int n, std::vector<bit_vector> &input_puzzle_values)
{
    assert(input_puzzle_values.size() == n*n);
    bit_vector input_as_bits;

    for (unsigned int i = 0; i < n*n; i++) {
        assert(input_puzzle_values[i].size() == 8);
        input_as_bits.insert(input_as_bits.end(), input_puzzle_values[i].begin(), input_puzzle_values[i].end());
    }
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}