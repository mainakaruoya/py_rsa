import argparse
# colorama is for coloring some of the output shown on the screen
from colorama import init as colorama_init, Fore, Style
from py_rsa import *
from rsa_primes import *


colorama_init()

parser = argparse.ArgumentParser(
    description="This is a CLI-based implementation of RSA. Takes a plaintext message, as well as the key size (2048, 3072, or 4096 bits), and the operation(s) to carry out - encryption (and decryption), signature generation (and verification), or both encryption and signing."
)

parser.add_argument("-m", "--message", metavar="<message>", type=str,
                          help="The message to be encrypted. Due to RSA's design (where the encoded message's integer representative should not be larger than the modulus), the message size is limited. This is especially noticeable where a smaller bit length for the modulus is selected, and a hash function with longer digest/larger digest size is chosen", required=True)

parser.add_argument("-k", "--keysize", metavar="<key size>", type=int, choices=[2048, 3072, 4096],
                    help="Size/length - in bits - of the key to be generated. Can be 2048, 3072, or 4096. While in theory the script generating the keys can generate primes with longer bit lengths, currently it takes much longer to generate such keys, and generally in practice, a modulus length of 4096 is appropriate for most use cases. In keeping with NIST FIPS 186-5 guidelines, the minimum possible modulus bit length is set at 2048 bits", required=True)


parser.add_argument("-f", "--function", metavar="<operation to carry out>", type=str, choices=[
                    "encrypt", "sign", "both"], help="This flag allows the user to choose the operation to carry out using RSA cryptosystem - encryption, generating a digital signature, or both. To achieve those operations, the user's choices are 'encrypt', 'sign', or 'both' respectively", required=True)


# This function calls the encryption and decryption procedures needed to encrypt and decrypt our message with the RSA keys
def encryptAndDecryptMessage(publicKeyToUse: tuple, privateKeyToUse: tuple, messageToHandle: bytes) -> None:
    
    print(f"Our message to encrypt:\n{Style.BRIGHT}{Fore.BLUE}{messageToHandle.decode("utf-8")}{Style.RESET_ALL}")    
    
    encryptedMessage = encryptionForRSAESwithOAEP(publicKeyToUse, messageToHandle)
    print(f"Our ciphertext:\n{Style.BRIGHT}{Fore.GREEN}{encryptedMessage.hex()}{Style.RESET_ALL}")
    
    decryptedMessage = decryptionForRSAESwithOAEP(privateKeyToUse, encryptedMessage)
    print(f"Our recovered message:\n{Style.BRIGHT}{Fore.YELLOW}{decryptedMessage.decode("utf-8")}{Style.RESET_ALL}\n")

# This function calls the relevant signature generation and verification schemes from the py_rsa.py file in order to generate as well as verify signatures
def signAndVerifyMessage(publicKeyToUse: tuple, privateKeyToUse: tuple, messageToHandle: bytes) -> None:

    print(f"Our message to sign:\n{Style.BRIGHT}{Fore.BLUE}{messageToHandle.decode("utf-8")}{Style.RESET_ALL}")    
    
    generatedSignature = signatureGenerationRSASSAwithPSS(privateKeyToUse, messageToHandle)
    print(f"Our signature is:\n{Style.BRIGHT}{Fore.GREEN}{generatedSignature.hex(':')}{Style.RESET_ALL}")
    
    signatureVerificationStatus = signatureVerificationRSASSAwithPSS(publicKeyToUse, messageToHandle, generatedSignature)
    print(f"Signature verification status:\n{Style.BRIGHT}{Fore.YELLOW}{signatureVerificationStatus}{Style.RESET_ALL}")

def generateKeyForOperation(expectedKeySize: int) -> tuple[tuple, tuple]:
    _, seedToUse = generateSeedForPrimesGeneration(expectedKeySize)
    _, p, q = generatePandQ(expectedKeySize, seedToUse)
    modulus, publicExponent, privateExponent, firstPrimeFactorP, secondPrimeFactorQ = generateKeyMaterial(expectedKeySize, (p, q))
    
    publicKey = (modulus, publicExponent)
    privateKey = (modulus, publicExponent, privateExponent, firstPrimeFactorP, secondPrimeFactorQ)
    
    return publicKey, privateKey

def parseInput() -> None:

    receivedArguments = parser.parse_args()
    message = receivedArguments.message
    keySize = receivedArguments.keysize
    functions: str = receivedArguments.function

    print(f"Our message is:\n{Style.BRIGHT}{Fore.BLUE}{message}{Style.RESET_ALL}")
    print(f"\nSelected size for the RSA modulus is:\n{Style.BRIGHT}{Fore.YELLOW}{keySize} bits{Style.RESET_ALL}")
    print(f"\nOperation(s) to carry out:\n{Style.BRIGHT}{Fore.GREEN}{functions.capitalize()}{Style.RESET_ALL}\n")

    print("---KEY GENERATION---")
    publicKeyToUse, privateKeyToUse = generateKeyForOperation(keySize)

    # This line handles user-supplied messages, since our algorithm only works with bytes.
    # We convert our message beforehand into bytes using this
    if type(message) != bytes:
        encodedValue = message.encode("utf-8")

    try:
        if functions.lower() == "encrypt":
            encryptAndDecryptMessage(publicKeyToUse, privateKeyToUse, encodedValue)

        if functions.lower() == "sign":
            signAndVerifyMessage(publicKeyToUse, privateKeyToUse, encodedValue)

        if functions.lower() == "both":
            encryptAndDecryptMessage(publicKeyToUse, privateKeyToUse, encodedValue)
            print(f"{Style.BRIGHT}-----------------------{Style.RESET_ALL}")
            signAndVerifyMessage(publicKeyToUse, privateKeyToUse, encodedValue)
    except:
        print("Error encountered. Please try again.")


if __name__ == "__main__":
    parseInput()
