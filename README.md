# Romulus software implementations protected against 1st-order side-channel attacks

This repository contain software implementations of [Romulus](https://romulusae.github.io/romulus/), one of the finalists of the [NIST LWC competition](https://csrc.nist.gov/projects/lightweight-cryptography).

These implementations were written to answer the [call for protected software implementations](https://cryptography.gmu.edu/athena/LWC/Call_for_Protected_Software_Implementations.pdf) issued by the [Cryptographic Engineering Research Group](https://cryptography.gmu.edu/) from George Mason University, and therefore follow the proposed API.

Note that the implementations require an external `randombytes` function with the following prototype:
`void randombytes(unsigned char *,unsigned long long);`
in order to generate the shares used as masks.

More details about the implementations and countermeasures are given in `Documents/documentation.pdf`.