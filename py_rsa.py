"""
An implementation of RSA that aims to be faithful to the PKCS #1 v2.2 RSA Cryptography Standard, as defined in `PKCS #1 v2.2, RSA Cryptography Standard` (and reprinted in `RFC 8017`).

Note: This script does not implement RSAES-PKCS1-v1_5 and RSASSA-PKCS1-v1_5.

To get keys for use with this file, generate them using the `rsa_primes.py` script.
"""

# This generic import allows the user to choose a suitable hash function for mask generation, or for encryption/decryption
import hashlib
from os import urandom
from math import ceil

# The error to raise when we experience a failure within the decryption operation of the RSA encryption scheme
class DecryptionException(Exception):
    pass

# The error to raise when we experience a failure within the decryption operation of the RSA encryption scheme
class VerificationException(Exception):
    pass

# These items are not necessarily part of the Class, for now, so they can be separated from it.
# Section 4: Data conversion primitives
# 4.1: I20SP
def integerToOctetString(integerToConvert: int, lengthOfOctetString: int) -> bytes:
    if integerToConvert >= pow(256, lengthOfOctetString):
        raise ValueError("Integer too large")
    else:
        return integerToConvert.to_bytes(length=lengthOfOctetString, byteorder='big')

# 4.2: OS2IP
def octetStringToInteger(octetStringToConvert: bytes) -> int:
    integerValue = int()
    return integerValue.from_bytes(octetStringToConvert, byteorder='big')


# Section 5: Cryptographic Primitives
# 5.1.1: Encryption primitive - RSAEP
def rsaEncryptionPrimitive(publicKey: tuple[int, int], messageRepresentative: int) -> int:
    modulus, publicExponent = publicKey
    
    if messageRepresentative > 0 and messageRepresentative < modulus:
        return pow(messageRepresentative, publicExponent, modulus)
    else:
        raise ValueError("Message representative out of range")
    
# 5.1.2: Decryption primitive - RSADP
def rsaDecryptionPrimitive(privateKey: tuple[int, int], ciphertextRepresentative: int) -> int:
    modulus, privateExponent = privateKey

    if ciphertextRepresentative > 0 and ciphertextRepresentative < modulus:
        return pow(ciphertextRepresentative, privateExponent, modulus)
    else:
        raise ValueError("Ciphertext representative out of range")

# 5.2.1: Signature primitive - RSASP1
def rsaSignaturePrimitive(privateKey: tuple[int, int], messageRepresentative: int) -> int:
    modulus, privateExponent = privateKey

    if messageRepresentative > 0 and messageRepresentative < modulus:
        return pow(messageRepresentative, privateExponent, modulus)
    else:
        raise ValueError("Ciphertext representative out of range")

# 5.2.2: Verification primitive - RSAVP1
def rsaSignatureVerificationPrimitive(publicKey: tuple[int, int], signatureRepresentative: int) -> int:
    modulus, publicExponent = publicKey
    
    if signatureRepresentative > 0 and signatureRepresentative < modulus:
        return pow(signatureRepresentative, publicExponent, modulus)
    else:
        raise ValueError("Signature representative out of range")


# Mask Generation Function
# Appendix B.2.1: MGF1, a mask generation function based on a hash function
def maskGenerationFunction1(seed: bytes, lengthOfMask: int, hashFunction=hashlib.sha256) -> bytes:
    # Our hash function is initialized as an object by virtue of how it is passed as an argument in our function definition.
    # As such, we have to call the update() and digest() methods to generate our hash value
    initializedHash = hashFunction()
    # The hash object has the attribute of digest_size that allows us to know how long (in bytes) the output will be
    hashLength = initializedHash.digest_size

    if lengthOfMask > (pow(2, 32) * hashLength):
        raise ValueError("Mask too long")
    
    maskToReturn = b''
    count = 0

    while len(maskToReturn) < lengthOfMask:
        temporaryOctetString = integerToOctetString(count, 4)
        initializedHash.update(seed)
        initializedHash.update(temporaryOctetString)
        hashValue = initializedHash.digest()
        maskToReturn += hashValue
        count += 1
        
    return maskToReturn[0:lengthOfMask]


# Section 7: Encryption Scheme
# 7.1: RSA Encryption Scheme with Optimal Asymmetric Encryption Padding (RSAES-OAEP).
# 7.1.1: RSAES-OAEP-Encrypt: Encryption Operation
# If the hash function chosen is SHA-256, use a key with 1024 bits or larger
def encryptionForRSAESwithOAEP(publicKey: tuple[int, int], messageToEncrypt: bytes, optionalLabel=b'', hashFunction=hashlib.sha256, maskGenerationFunction=maskGenerationFunction1) -> bytes:
    """
    (RSAES-OAEP) RSA Encryption Scheme with Optimal Asymmetric Encryption Padding - encryption operation.
    
    Utilizes EME-OAEP encoding to encode the message.
    """

    print("\n---ENCRYPTION OPERATION---")

    modulus, _ = publicKey
    initializedHash = hashFunction()
    hashLength = initializedHash.digest_size
    modulusLength = ceil(modulus.bit_length() / 8)

    if len(optionalLabel) > (pow(2, 61) - 1):
        raise ValueError("Label too long")
    
    maximumMessageLength = modulusLength - (2 * hashLength) - 2

    if len(messageToEncrypt) > maximumMessageLength:
        raise ValueError("Message too long")
    
    #---start of EME-OAEP encoding---
    initializedHash.update(optionalLabel)
    hashOfLabel = initializedHash.digest()
    
    lengthOfPaddingNeeded = maximumMessageLength - len(messageToEncrypt)

    if lengthOfPaddingNeeded > 0:
        paddingString = bytes(lengthOfPaddingNeeded)
    
    dataBlock = hashOfLabel + paddingString + b'\x01' + messageToEncrypt

    seed = urandom(hashLength)

    maskLength = modulusLength - len(hashOfLabel) - 1
    dataBlockMask = maskGenerationFunction(seed, maskLength)
    maskedDataBlock = bytes(a ^ b for a, b in zip(dataBlock, dataBlockMask, strict=True))

    seedMask = maskGenerationFunction(maskedDataBlock, hashLength)
    maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask, strict=True))
    
    encodedMessage: bytes = b'\x00' + maskedSeed + maskedDataBlock
    #---end of EME-OAEP encoding---
    
    # Encryption of EME-OAEP encoded message
    messageRepresentative = octetStringToInteger(encodedMessage)
    ciphertext = rsaEncryptionPrimitive(publicKey, messageRepresentative)
    
    return integerToOctetString(ciphertext, modulusLength)

# 7.1.2: RSAES-OAEP-Decrypt: Decryption Operation
def decryptionForRSAESwithOAEP(privateKey: tuple[int, int, int, int, int], ciphertextToDecrypt: bytes, optionalLabel=b'', hashFunction=hashlib.sha256, maskGenerationFunction=maskGenerationFunction1) -> bytes:
    """
    (RSAES-OAEP) RSA Encryption Scheme with Optimal Asymmetric Encryption Padding - decryption operation.
    Utilizes EME-OAEP decoding to decode the message.

    The function emits a generic error message, 'decryption error' in keeping with the recommendation found in PKCS #1 v2.2, p. 23
    """

    print("\n---DECRYPTION OPERATION---")
    # privateKey is currently a 5-tuple (n, e, d, p, q). We only need n and d, and not the other values, hence this deconstruction below.
    modulus, _, privateExponent, _, _ = privateKey

    initializedHash = hashFunction()
    hashLength = initializedHash.digest_size

    modulusLength = ceil(modulus.bit_length() / 8)

    minimumCiphertextLength = (hashLength * 2) + 2
    maskedDataBlockLength = modulusLength - hashLength - 1

    if len(optionalLabel) > (pow(2, 61) - 1):
        raise ValueError("Label too long")
    
    if len(ciphertextToDecrypt) != modulusLength:
        raise DecryptionException("Decryption error")
    
    if modulusLength < minimumCiphertextLength:
        raise DecryptionException("Decryption error")
    
    # RSA decryption proper
    ciphertextRespresentative = octetStringToInteger(ciphertextToDecrypt)
    try:
        messageRepresentative = rsaDecryptionPrimitive((modulus, privateExponent), ciphertextRespresentative)
    except ValueError:
        print("Decryption error")

    encodedMessage = integerToOctetString(messageRepresentative, modulusLength)

    #---start of EME-OAEP decoding---
    # We extract the initial value, which we expect to be 0 (0x0); if it is not 0x0, we emit a decryption error. In the standard, this initial byte is called Y
    initialByte = encodedMessage[0]
    maskedSeed = encodedMessage[1:(hashLength + 1)]
    maskedDataBlock = encodedMessage[(hashLength + 1):]

    seedMask = maskGenerationFunction(maskedDataBlock, hashLength)
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask, strict=True))

    dataBlockMask = maskGenerationFunction(seed, maskedDataBlockLength)
    dataBlock = bytes(a ^ b for a, b in zip(maskedDataBlock, dataBlockMask, strict=True))
    #---end of EME-OAEP decoding---

    decodedHashOfLabel = dataBlock[:hashLength]
    initializedHash.update(optionalLabel)
    hashOfLabel = initializedHash.digest()

    if hashOfLabel != decodedHashOfLabel:
        raise DecryptionException("Decryption error")
    
    if initialByte != 0:
        raise DecryptionException("Decryption error")
    
    messageWithPadding = dataBlock[hashLength:]
    
    # The point of recoveryIndex is to store the index value of \x01. Once we get this index, we simply print what comes after it. If \x01 doesn't exist, we raise an exception.
    # \x01 is what split our padding string (if it exists) from our message proper.
    recoveryIndex = messageWithPadding.find(b'\x01')

    if recoveryIndex != -1:
        originalMessage = messageWithPadding[(recoveryIndex + 1):]
    else:
        raise DecryptionException("Decryption error")

    return originalMessage


# Section 9: Encoding Method for Signatures with Appendix, utilizing Probabilistic Signature Scheme (EMSA-PSS)
# Used by the signature scheme operations below
# 9.1.1: EMSA-PSS-Encode: Encoding Operation
# saltLength set to a default of 0 in keeping with the guidance found in PKCS #1 v2.2, p. 36. It could either be that, or the digest size of the hash function used by this operation
def encodingForEMSAwithPSS(messageToEncode: bytes, encodedMessageBitLength: int, hashFunction=hashlib.sha256, maskGenerationFunction=maskGenerationFunction1, saltLength=0) -> bytes:

    if len(messageToEncode) > (pow(2, 61) - 1):
        raise ValueError("Label too long")
    
    initializedHash = hashFunction()
    hashLength = initializedHash.digest_size
    initializedHash.update(messageToEncode)
    messageHash = initializedHash.digest()

    encodedMessageLength = ceil(encodedMessageBitLength / 8)
    if encodedMessageLength < (hashLength + saltLength + 2):
        raise Exception("Encoding error")
    
    salt = urandom(saltLength)
    
    # What we are here calling paddedMessage is in the standard called M'
    paddedMessage = bytes(8) + messageHash + salt
    secondHash = hashFunction()
    secondHash.update(paddedMessage)
    paddedMessageHash = secondHash.digest()

    paddingLength = encodedMessageLength - len(salt) - hashLength - 2
    paddingString = bytes(paddingLength)

    dataBlock: bytes = paddingString + b'\x01' + salt
    dataBlockMask = maskGenerationFunction(paddedMessageHash, len(dataBlock))
    maskedDataBlock = bytes(a ^ b for a, b in zip(dataBlock, dataBlockMask, strict=True))

    # TODO: Make this more efficient
    # This part helps us fulfil step 11 of what is described in Section 9.1.1. It produces what we here call `newMaskedDataBlock`
    bitsToAlter = (8 * encodedMessageLength) - encodedMessageBitLength
    newFirstOctet = maskedDataBlock[0] & (255 >> bitsToAlter)
    newMaskedDataBlock = newFirstOctet.to_bytes() + maskedDataBlock[1:]

    encodedMessage: bytes = newMaskedDataBlock + paddedMessageHash + b'\xbc'

    return encodedMessage

# 9.1.2: EMSA-PSS-Verify: Verification Operation
def verificationForEMSAwithPSS(message: bytes, encodedMessage: bytes, encodedMessageBitLength: int, hashFunction=hashlib.sha256, maskGenerationFunction=maskGenerationFunction1, saltLength=0) -> str:

    if len(message) > (pow(2, 61) - 1):
        return "inconsistent"
    
    initializedHash = hashFunction()
    hashLength = initializedHash.digest_size
    initializedHash.update(message)
    messageHash = initializedHash.digest()

    encodedMessageLength = ceil(encodedMessageBitLength / 8)
    if encodedMessageLength < hashLength + saltLength + 2:
        return "inconsistent"
    
    if encodedMessage[-1] != 0xbc:
        return "inconsistent"
    
    maskedDataBlockLength = encodedMessageLength - hashLength - 1
    maskedDataBlock = encodedMessage[:maskedDataBlockLength]
    originalMessageHash = encodedMessage[maskedDataBlockLength:(maskedDataBlockLength + hashLength)]

    # These lines help us check if a specific number of the leftmost octet of the maskedDataBlock are equal to zero - step 6 of 9.1.2
    firstOctet = maskedDataBlock[0]
    alteredBits = (8 * encodedMessageLength) - encodedMessageBitLength
    if firstOctet > (255 >> alteredBits):
        return "inconsistent"
    
    dataBlockMask = maskGenerationFunction(originalMessageHash, maskedDataBlockLength)
    dataBlock = bytes(a ^ b for a, b in zip(maskedDataBlock, dataBlockMask, strict=True))
    newFirstOctet = dataBlock[0] & (255 >> alteredBits)
    newDataBlock = newFirstOctet.to_bytes() + dataBlock[1:]

    zeroPadding = encodedMessageLength - hashLength - saltLength - 2
    if newDataBlock[:zeroPadding] != bytes(zeroPadding):
        return "inconsistent"
    
    byteIndex = maskedDataBlockLength - saltLength
    if newDataBlock[byteIndex - 1] != 0x1:
        return "inconsistent"
    
    if saltLength > 0:
        salt = newDataBlock[-saltLength:-1]
    else:
        salt = b''

    paddedMessage = bytes(8) + messageHash + salt
    secondHash = hashFunction()
    secondHash.update(paddedMessage)
    paddedMessageHash = secondHash.digest()
    if originalMessageHash == paddedMessageHash:
        return "consistent"
    else:
        return "inconsistent"


# Section 8: Signature Scheme with Appendix
# 8.1: RSA Signature Scheme with Appendix, utilizing a Probabilistic Signature Scheme (RSASSA-PSS)
# 8.1.1: RSASSA-PSS-Sign: Signature Generation Operation
def signatureGenerationRSASSAwithPSS(privateKey: tuple[int, int], messageToSign: bytes) -> bytes:

    print("\n---SIGNATURE GENERATION---")

    modulus, _, privateExponent, _, _ = privateKey
    modulusBitLength = modulus.bit_length()
    modulusLength = ceil(modulusBitLength / 8)
    # encodedMessageLength = ceil((modulusBitLength - 1) / 8)

    # EMSA-PSS encoding
    encodedMessage = encodingForEMSAwithPSS(messageToSign, (modulusBitLength - 1))
    
    # RSA Signature
    messageRepresentative = octetStringToInteger(encodedMessage)
    signatureRepresentative = rsaSignaturePrimitive((modulus, privateExponent), messageRepresentative)
    messageSignature = integerToOctetString(signatureRepresentative, modulusLength)

    return messageSignature

# 8.1.2: RSASSA-PSS-Verify: Signature Verification Operation
def signatureVerificationRSASSAwithPSS(publicKey: tuple[int, int], message: bytes, signatureToVerify: bytes) -> str:

    print("\n---SIGNATURE VERIFICATION---")

    modulus, publicExponent = publicKey
    modulusBitLength = modulus.bit_length()
    modulusLength = ceil(modulusBitLength / 8)

    # Length checking
    if len(signatureToVerify) != modulusLength:
        raise VerificationException("Invalid signature")
    
    # RSA verification
    signatureRepresentative = octetStringToInteger(signatureToVerify)
    try:
        messageRepresentative = rsaSignatureVerificationPrimitive((modulus, publicExponent), signatureRepresentative)
    except ValueError:
        raise VerificationException("Invalid signature")
    
    encodedMessageLength = ceil((modulusBitLength - 1) / 8)
    try:
        encodedMessage = integerToOctetString(messageRepresentative, encodedMessageLength)
    except ValueError:
        raise VerificationException("Invalid signature")
    
    # EMSA-PSS Verification
    try:
        verificationResult = verificationForEMSAwithPSS(message, encodedMessage, (modulusBitLength - 1))
    except:
        print("Invalid signature")

    if verificationResult == "consistent":
        return "Valid signature"
    else:
        raise VerificationException("Invalid signature")


if __name__ == '__main__':
    
    largerPublicKey = (91756414765513640411076598816732229531757047368878964277753080447375639837259159860063635956738745623323847458803835495326009593690699654197106252194865602200528792601274750066788611320504328608499564806672365336049034845195449869950775798318990493758365377989192138112613427412772233605359203744429824547651, 65537)
    largerPrivateKey = (91756414765513640411076598816732229531757047368878964277753080447375639837259159860063635956738745623323847458803835495326009593690699654197106252194865602200528792601274750066788611320504328608499564806672365336049034845195449869950775798318990493758365377989192138112613427412772233605359203744429824547651, 65537, 49255877258121906454401114225116446696625489166189035846249158844913901843456589453848952142973065745672769236434040870974630262533111136217837157035756920205208139131611114046010882643251893843488696079035217629058311416851419630465585849018946388888093568169978395994040625638136696169049252973491570159529, 36889661052031723872281362738704133425434010732310073165891424395035850708156114974002814316296616150131935741698416808477268431184638808297016677836549271155307677, 2487320624499478607170971031083659374813268746919521411441469791454475560158672378195069007006448939923080575736920049475463898646632249228532063)

    # RSA encryption example/testing
    exampleKey = urandom(32)
    print(f"Our message to encrypt - assume we have the AES-256 key:\n{exampleKey.hex(':')}")
    cipherLargeKey = encryptionForRSAESwithOAEP(largerPublicKey, exampleKey)
    print(f"Our ciphertext:\n{cipherLargeKey.hex()}")
    decipherLargeKey = decryptionForRSAESwithOAEP(largerPrivateKey, cipherLargeKey)
    print(f"Our recovered message:\n{decipherLargeKey.hex(':')}\n")

    # RSA digital signature example/testing - two instances
    messageToSign = urandom(16)
    print(f"Our message to sign - assume we want to sign the following value:\n{messageToSign.hex(':')}")
    generatedSignature = signatureGenerationRSASSAwithPSS(largerPrivateKey, messageToSign)
    print(f"Our signature is:\n{generatedSignature.hex(':')}")
    verificationStatus = signatureVerificationRSASSAwithPSS(largerPublicKey, messageToSign, generatedSignature)
    print(f"Signature verification status:\n{verificationStatus}")
    #-----------
    message = "Hello world, I am Joseph!".encode("utf-8")
    print(f"\nOur initial message:\n{message.decode('utf-8')}")
    newSignature = signatureGenerationRSASSAwithPSS(largerPrivateKey, message)
    print(f"Our signature is:\n{newSignature.hex(':')}")
    verificationStatus = signatureVerificationRSASSAwithPSS(largerPublicKey, message, newSignature)
    print(f"Signature verification status:\n{verificationStatus}")

    """
    TODO: link the initialized values for the RSACryptoystem class with whatever operations we'd want to perform
    """