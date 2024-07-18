### Rivest-Shamir-Adleman (RSA) Public-Key Cryptosystem
This is an implementation of the RSA public-key cryptosystem that aims to be faithful to the PKCS #1 v2.2 RSA Cryptography Standard (which has also been reprinted in RFC 8017). The code implements the RSAES-OAEP encryption scheme and the RSASSA-PSS signature scheme with appendix.

The RSA Standard and its reprint are linked below:
1. [PKCS #1 v2.2, RSA Cryptography Standard](https://datatracker.ietf.org/doc/html/rfc8017)
2. [RFC 8017 - PKCS #1: RSA Cryptography Specifications Version 2.2](https://www.karlin.mff.cuni.cz/~kozlik/udk_mat/pkcs1.pdf)

**Note:** This implementation does not implement the older versions of the encryption and signature schemes, **RSAES-PKCS1-v1_5** and **RSASSA-PKCS1-v1_5** respectively.

The implementation is split into three components: The file containing the RSA code proper (`py_rsa.py`), a script to generate the keys to be used by the RSA cryptosystem (`rsa_primes.py`), and a script that allows us to use the RSA cryptosystem via CLI (`rsa-cli.py`).

The script for generating the primes has largely followed techniques contained in **NIST FIPS 186-5, Digital Signature Standard,** especially in the appendices. As a point of note, this script aims to generate *provable* primes, per the guidelines in Appendix A.1.2 (and the other sections it references). The .pdf version of the FIPS Standard is found [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf), whilst the web page for the same is found [here](https://csrc.nist.gov/pubs/fips/186-5/final).

### ⚠️ Disclaimer
Though this implementation aimed to follow the standard as closely as possible, it is **not recommended** to use this in a production environment. It is better to use libraries like `rsa`, `Cryptogrpahy`, `PyNaCl` and `Pycryptodome` which have been more thoroughly vetted and importantly, generally optimized for such use. You will notice the slowness of key generation when you select a key with a modulus of length 4096 bits.

### Prerequisites
The plaintext, ciphertext, signature, and the decoded plaintext are color-coded using `colorama`, hence the need to install it using pip:
`pip install colorama`

### Usage
##### `py_rsa.py`
Since it is defined as a kind of module, you can import its functionality into your program. You can use `rsa_primes.py` script to generate the primes and create the keys to use. 

##### `rsa_primes.py`
This generates the primes needed to create the public and private keys, as well as creating the public and private keys. Once the fundamental primes, p and q, are generates, the keys are packed into tuples that have the following structure: 
Public key tuple: `(modulus, public_exponent)`
Private key tuple: `(modulus, public_exponent, private_exponent, p, q)`

For now, at least, the program does not generate a `.pem` file that stores the private key.

##### `rsa_cli.py`
This is the CLI implementation of the cryptosystem, which calls `rsa_primes.py` to generate keys, and then with the user-supplied message, calls the relevant functionality from `py_rsa.py`.

The command to use (all arguments are mandatory): `rsa_cli.py [-h] -m <message> -k <key size> -f <operation to carry out>`

~~~
options:
  -h, --help            show this help message and exit
  -m <message>, --message <message>
                        The message to be encrypted. Due to RSA's design (where the encoded message's integer representative should not be larger than the
                        modulus), the message size is limited. This is especially noticeable where a smaller bit length for the modulus is selected, and a hash      
                        function with longer digest/larger digest size is chosen
  -k <key size>, --keysize <key size>
                        Size/length - in bits - of the key to be generated. Can be 2048, 3072, or 4096. In keeping with NIST FIPS 186-5 guidelines, the minimum possible modulus bit length is set at 2048 bits   
  -f <operation to carry out>, --function <operation to carry out>
                        This flag allows the user to choose the operation to carry out using RSA cryptosystem - encryption, generating a digital signature, or       
                        both. To achieve those operations, the user's choices are 'encrypt', 'sign', or 'both' respectively
~~~

#### Other Useful Links
The first two links are discussions on the _Cryptography StackExchange_ that proved to be very useful in discovering how to generate primes. The third is a link to FIPS 140-2 Implementation Guidance, which on p. 126 gives a formula for calculating the security strength of a given modulus bit length whose security strength is not pre-defined in NIST SP 800-57 part 1, Revision 5. 
- [How can I generate large prime numbers for RSA?](https://crypto.stackexchange.com/questions/71/how-can-i-generate-large-prime-numbers-for-rsa)
- [How are primes generated for RSA?](https://crypto.stackexchange.com/questions/1970/how-are-primes-generated-for-rsa)
- [Implementation Guidance for FIPS 140-2 and the Cryptographic Module Validation Program (October 20, 2023 update)](https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/fips140-2/fips1402ig.pdf)