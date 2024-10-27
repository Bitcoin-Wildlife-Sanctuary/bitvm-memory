# bitvm-memory
A memory abstraction in BitVM

### Blake3ic

This repository contains a modified version of Blake3, which we call Blake3ic where `ic` stands for infinite chunk. This 
is a version of Blake3 where the chunk size is not 1KiB, but infinite. In our use case, we always use one chunk.

We are confident in the security of doing so, based on [the Blake3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf). 
First of all, one can understand Blake3 as a primitive/compression together
with a mode of operation. The primitive of Blake3 consists of the round function and the output truncation that gives a
"fixed-length" hash function, and the mode of operation is the way to extend it into a hash function that supports longer
input. What we do is mostly modifying the mode of operation. This new mode of operation, which changes the chunk size,
does not affect the three requirements: subtree-freeness, radical-decodability, and message-completeness. Moreover, the
Blake3 paper also has a discussion about why it chose 1KiB as the chunk size, for which security is not a reason, but it is for
performance in terms of hashing long input in parallel.

### Acknowledgment and Credits

The Blake3 implementation is from [Fairgate Labs](https://github.com/FairgateLabs). 