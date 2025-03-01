# Section 3 
# - [ ] A MUST NOT consider the protocol complete until it receives and verifies cB.
# - [ ] Likewise, B MUST NOT consider the protocol complete until it receives and verifies cA.

# Section 3.3 
# - [ ] K is a shared value, though it MUST NOT be used or output as a shared secret from the protocol. Both A and B must
# - [ ] If an identity is absent, it is encoded as a zero-length string.
#   This MUST only be done for applications in which identities are implicit

# Section 4
# - [ ] Applications MUST specify this encoding, typically by referring to the document defining the group. 
# A MUST send B a key confirmation message so that both parties agree upon these shared secrets. The confirmation message cA is computed as a MAC over the protocol transcript TT, using KcA as follows: cA = MAC(KcA, TT). Similarly, B MUST send A a confirmation message using a MAC 
# Keys MUST be at least 128 bits in length.

# Section 5
# - [ ] This variant MUST be used when it is not possible to determine whether A or B should use M (or N),
#       - I.e. when the group is not known


# Section 7
# - [ ] check group membership of received elements from peers Section 7
# - [ ] The choices of random numbers MUST be uniform. Randomly generated values, e.g., x and y, MUST NOT be reused
#       - It is RECOMMENDED to generate these uniform numbers using rejection sampling# 
# - [ ] Some implementations of elliptic curve multiplication may leak information about the length of the scalar. These MUST NOT be used.
# - [ ]  Hashing of the transcript may take time depending only on the length of the transcript but not the contents
# - [ ] The HMAC keys in this document are shorter than recommended in [RFC8032]


# SHOULDS
# Section 3.2
# - [ ] For elliptic curves other than the ones in this document, the methods described in [RFC9380] SHOULD be used to generate M and N, e.g.,
# - [ ] The hashing algorithm SHOULD be an MHF so as to slow down brute-force attackers.
# -- might not be true
# Section 7
# - [ ] Applications that need augmented PAKEs should use the key confirmation mechanism
