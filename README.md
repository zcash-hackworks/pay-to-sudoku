# pay-to-sudoku

**Author**: Sean Bowe

This work was presented at Financial Cryptography 2016 and at <https://bitcoincore.org/en/2016/02/26/zero-knowledge-contingent-payments-announcement/>.
We thank Gregory Maxwell for the idea of ZKCPs, and for useful feedback and for participating in our demonstration. We also thank Pieter Wuille, Andrew Poelstra, and Madars Virza for helping with the demonstration.

WARNING: This is not really zero-knowledge (buyer can learn sudoku contents) as shown in the [ZKCSP paper](http://stevengoldfeder.com/papers/ZKCSP.pdf). [Attack implementation](https://github.com/matteocam/pay-to-sudoku-attack), [Fix implementation](https://github.com/matteocam/zkcsp-over-bitcoin) 

---------------------------

This is an implementation of a zero-knowledge contingent 
payment for paying someone to solve a sudoku puzzle.

```
./get-libsnark
make
cargo run gen 2 # generate circuit for 2^2 x 2^2 puzzle
cargo run test 2 # test the proofs
cargo run serve 2 # run a server on port 25519 for buying solutions
cargo run client 2 # run a client for selling solutions
```

# circuit description for some NxN puzzle:

**primary inputs**: sodoku puzzle `P`, key commitment `C`, encrypted solution `E`

**auxillary inputs**: solution `S`, key `K`

**properties:**

* **puzzle subset**: `S` must be a subset of `P` (the solution must complete the puzzle)
* **solution closure**: `S` must be closed under rows, columns and groups of the solution (the solution must be correct)
* **encryption correctness**: `E` must be `S` encrypted with `K` (using a stream cipher produced from SHA256)
* **solution commitment**: `C` must be `SHA256(K)`

**usage:**

Alice produces puzzle `P` and sends Bob `P` and the zk-SNARK proving key. Bob finds a solution `S` for the puzzle
and constructs `K`, `C`, and `E`. Bob constructs a `Proof`. Bob sends Alice (Proof, `C`, `E`). Alice verifies the
proof. Alice sends a CLTV transaction over the blockchain to Bob with the added constraint that Bob must produce
the preimage of `C` (aka `K`). After Bob redeems the TxOut, Alice uses `K` to decrypt `E`, producing `S`. If Bob
does not redeem the TxOut, Alice recovers her value but does not obtain `S`.
