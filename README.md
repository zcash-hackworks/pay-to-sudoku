# todo

* automated sudoku solver
* cache pk/vk
* clean up code
* bitcoin transaction stuff

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

todo:

* write better tests
* write interface for interacting with the snark
