template<typename FieldT>
sodoku_encryption_key<FieldT>::sodoku_encryption_key(protoboard<FieldT> &pb,
                                               unsigned int dimension,
                                               pb_variable_array<FieldT> &seed_key
                                               ) : gadget<FieldT>(pb, FMT(annotation_prefix, " sodoku_closure_gadget")),
                                                   seed_key(seed_key), dimension(dimension)
{
    assert(seed_key.size() == (256-8));
    unsigned int num_key_digests = div_ceil(dimension * dimension * 8, 256);

    padding_var.reset(new digest_variable<FieldT>(pb, 256, "padding"));

    key.resize(num_key_digests);
    salts.resize(num_key_digests);
    key_blocks.resize(num_key_digests);
    key_sha.resize(num_key_digests);

    // IV for SHA256
    pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

    for (unsigned int i = 0; i < num_key_digests; i++) {
        key[i].reset(new digest_variable<FieldT>(pb, 256, "key[i]"));
        salts[i].allocate(pb, 8, "key salt");
        key_blocks[i].reset(new block_variable<FieldT>(pb, {
            seed_key,
            salts[i],
            padding_var->bits
        }, "key_blocks[i]"));

        key_sha[i].reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                              IV,
                                                              key_blocks[i]->bits,
                                                              *key[i],
                                                              "hash"));
    }
}

template<typename FieldT>
void sodoku_encryption_key<FieldT>::generate_r1cs_constraints()
{
    unsigned int num_key_digests = div_ceil(dimension * dimension * 8, 256);

    padding_var->generate_r1cs_constraints(); // TODO: probably unnecessary

    for (unsigned int i = 0; i < 256; i++) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                { padding_var->bits[i] },
                { 1 },
                { sha256_padding[i] ? 1 : 0 }),
            "constrain_padding");
    }

    for (unsigned int i = 0; i < num_key_digests; i++) {
        key[i]->generate_r1cs_constraints();

        auto s = convertIntToVector(i);

        for (unsigned int j = 0; j < 8; j++) {
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { salts[i][j] },
                    { 1 },
                    { s[j] ? 1 : 0 }),
                "constrain_salts");
        }

        key_sha[i]->generate_r1cs_constraints();
    }
}

template<typename FieldT>
void sodoku_encryption_key<FieldT>::generate_r1cs_witness()
{
    unsigned int num_key_digests = div_ceil(dimension * dimension * 8, 256);

    for (unsigned int i = 0; i < 256; i++) {
        this->pb.val(padding_var->bits[i]) = sha256_padding[i] ? 1 : 0;
    }

    for (unsigned int i = 0; i < num_key_digests; i++) {
        auto s = convertIntToVector(i);

        for (unsigned int j = 0; j < 8; j++) {
            this->pb.val(salts[i][j]) = s[j] ? 1 : 0;
        }

        key_sha[i]->generate_r1cs_witness();
    }
}

template<typename FieldT>
sodoku_closure_gadget<FieldT>::sodoku_closure_gadget(protoboard<FieldT> &pb,
                                               unsigned int dimension,
                                               std::vector<pb_variable_array<FieldT>> &flags
                                               ) : gadget<FieldT>(pb, FMT(annotation_prefix, " sodoku_closure_gadget")),
                                                   dimension(dimension), flags(flags)
{
    assert(flags.size() == dimension);
}

template<typename FieldT>
void sodoku_closure_gadget<FieldT>::generate_r1cs_constraints()
{
    for (unsigned int i=0; i<dimension; i++) {
        linear_combination<FieldT> sum;

        for (unsigned int j=0; j<dimension; j++) {
            sum = sum + flags[j][i];
        }

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, 1, sum), "balance");
    }
}

template<typename FieldT>
void sodoku_closure_gadget<FieldT>::generate_r1cs_witness()
{
    
}



template<typename FieldT>
sodoku_cell_gadget<FieldT>::sodoku_cell_gadget(protoboard<FieldT> &pb,
                                               unsigned int dimension,
                                               pb_linear_combination<FieldT> &number
                                               ) : gadget<FieldT>(pb, FMT(annotation_prefix, " sodoku_cell_gadget")),
                                                   number(number), dimension(dimension)
{
    flags.allocate(pb, dimension, "flags for each possible number");
}

template<typename FieldT>
void sodoku_cell_gadget<FieldT>::generate_r1cs_constraints()
{
    for (unsigned int i = 0; i < dimension; i++) {
        generate_boolean_r1cs_constraint<FieldT>(this->pb, flags[i], "enforcement bitness");

        // this ensures that any flag that is set ENFORCES that the number
        // is i + 1. as a result, at most one flag can be set.
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(number - (i+1), flags[i], 0), "enforcement");
    }
}

template<typename FieldT>
void sodoku_cell_gadget<FieldT>::generate_r1cs_witness()
{
    for (unsigned int i = 0; i < dimension; i++) {
        if (this->pb.lc_val(number) == (i+1)) {
            this->pb.val(flags[i]) = FieldT::one();
        } else {
            this->pb.val(flags[i]) = FieldT::zero();
        }
    }
}

template<typename FieldT>
sodoku_gadget<FieldT>::sodoku_gadget(protoboard<FieldT> &pb, unsigned int n) :
        gadget<FieldT>(pb, FMT(annotation_prefix, " l_gadget"))
{
    dimension = n * n;

    const size_t input_size_in_bits = dimension * dimension * 8;
    {
        const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
        input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
        this->pb.set_input_sizes(input_size_in_field_elements);
    }

    puzzle_enforce.allocate(pb, dimension*dimension, "puzzle solution subset enforcement");

    puzzle_values.resize(dimension*dimension);
    puzzle_numbers.resize(dimension*dimension);
    solution_values.resize(dimension*dimension);
    solution_numbers.resize(dimension*dimension);
    cells.resize(dimension*dimension);

    for (unsigned int i = 0; i < (dimension*dimension); i++) {
        puzzle_values[i].allocate(pb, 8, "puzzle_values[i]");
        solution_values[i].allocate(pb, 8, "solution_values[i]");

        puzzle_numbers[i].assign(pb, pb_packing_sum<FieldT>(pb_variable_array<FieldT>(puzzle_values[i].rbegin(), puzzle_values[i].rend())));
        solution_numbers[i].assign(pb, pb_packing_sum<FieldT>(pb_variable_array<FieldT>(solution_values[i].rbegin(), solution_values[i].rend())));

        input_as_bits.insert(input_as_bits.end(), puzzle_values[i].begin(), puzzle_values[i].end());

        cells[i].reset(new sodoku_cell_gadget<FieldT>(this->pb, dimension, solution_numbers[i]));
    }

    closure_rows.resize(dimension);
    closure_cols.resize(dimension);
    closure_groups.resize(dimension);

    for (unsigned int i = 0; i < dimension; i++) {
        std::vector<pb_variable_array<FieldT>> row_flags;
        std::vector<pb_variable_array<FieldT>> col_flags;
        for (unsigned int j = 0; j < dimension; j++) {
            row_flags.push_back(cells[i*dimension + j]->flags);
            col_flags.push_back(cells[j*dimension + i]->flags);
        }

        closure_rows[i].reset(new sodoku_closure_gadget<FieldT>(this->pb, dimension, row_flags));
        closure_cols[i].reset(new sodoku_closure_gadget<FieldT>(this->pb, dimension, col_flags));
    }

    for (unsigned int gi = 0; gi < dimension; gi++) {
        std::vector<pb_variable_array<FieldT>> group_flags;
        unsigned int start_row = (gi / n) * n;
        unsigned int start_col = (gi % n) * n;

        for (unsigned int i = start_row; i < (start_row + n); i++) {
            for (unsigned int j = start_col; j < (start_col + n); j++) {
                group_flags.push_back(cells[i*dimension + j]->flags);
            }
        }

        closure_groups[gi].reset(new sodoku_closure_gadget<FieldT>(this->pb, dimension, group_flags));
    }

    seed_key.reset(new digest_variable<FieldT>(pb, 256, "seed_key"));

    pb_variable_array<FieldT> seed_key_cropped(seed_key->bits.begin(), seed_key->bits.begin() + (256 - 8));
    key.reset(new sodoku_encryption_key<FieldT>(pb, dimension, seed_key_cropped));

    assert(input_as_bits.size() == input_size_in_bits);
    unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));
}

template<typename FieldT>
void sodoku_gadget<FieldT>::generate_r1cs_constraints()
{
    for (unsigned int i = 0; i < (dimension*dimension); i++) {
        for (unsigned int j = 0; j < 8; j++) {
            // ensure bitness
            generate_boolean_r1cs_constraint<FieldT>(this->pb, solution_values[i][j], "solution_bitness");
        }

        // enforce solution is subset of puzzle

        // puzzle_enforce[i] must be 0 or 1
        generate_boolean_r1cs_constraint<FieldT>(this->pb, puzzle_enforce[i], "enforcement bitness");

        // puzzle_enforce[i] must be 1 if puzzle_numbers[i] is nonzero
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(puzzle_numbers[i], 1 - puzzle_enforce[i], 0), "enforcement");
        
        // solution_numbers[i] must equal puzzle_numbers[i] if puzzle_enforce[i] is 1
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(puzzle_enforce[i], (solution_numbers[i] - puzzle_numbers[i]), 0), "enforcement equality");
    
        // enforce cell constraints
        cells[i]->generate_r1cs_constraints();
    }

    for (unsigned int i = 0; i < dimension; i++) {
        closure_rows[i]->generate_r1cs_constraints();
        closure_cols[i]->generate_r1cs_constraints();
        closure_groups[i]->generate_r1cs_constraints();
    }

    seed_key->generate_r1cs_constraints();
    key->generate_r1cs_constraints();

    unpack_inputs->generate_r1cs_constraints(true);
}

template<typename FieldT>
void sodoku_gadget<FieldT>::generate_r1cs_witness(std::vector<bit_vector> &input_puzzle_values,
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

        puzzle_numbers[i].evaluate(this->pb);
        solution_numbers[i].evaluate(this->pb);

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

        cells[i]->generate_r1cs_witness();
    }

    key->generate_r1cs_witness();

    unpack_inputs->generate_r1cs_witness_from_bits();
}

template<typename FieldT>
r1cs_primary_input<FieldT> sodoku_input_map(unsigned int n, std::vector<bit_vector> &input_puzzle_values)
{
    unsigned int dimension = n*n;
    assert(input_puzzle_values.size() == dimension*dimension);
    bit_vector input_as_bits;

    for (unsigned int i = 0; i < dimension*dimension; i++) {
        assert(input_puzzle_values[i].size() == 8);
        input_as_bits.insert(input_as_bits.end(), input_puzzle_values[i].begin(), input_puzzle_values[i].end());
    }
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}