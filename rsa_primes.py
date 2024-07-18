"""
This script enables us generate the primes needed for our RSA cryptosystem.

It follows the guidance contained in FIPS 186-5, Digital Signature Standard. Specifically, it generates provable primes in line with Appendix A.1.2 of that standard.

Where the user desires to use a different hash function, I think it should be consistent across the different functions that use a hash function.
"""

from math import gcd, lcm, ceil, log, sqrt, floor
from secrets import randbits
import hashlib
from decimal import *

# Dictionary with hardcoded security strengths for certain keys with the structure - bit_length : security_strength
# Formula taken from p. 126 of Implementation Guidance for FIPS 140-2 (October 30, 2023 update)
SECURITY_STRENGTHS = {
    2048: 112,
    3072: 128,
    7680: 192,
    15360: 256,
}

# Other constants, which are strings for SUCCESS and FAILURE
SUCCESS = "SUCCESS"
FAILURE = "FAILURE"

# This function is used to calculate the security strengths not in the SECURITY_STRENGTHS dictionary above. It will account for all possible key sizes (modulus bit lengths) that may be entered by a user.
# Formula taken from p. 126 of Implementation Guidance for FIPS 140-2 (October 30, 2023 update)
def calculateSecurityStrength(bitLengthOfKey: int) -> int:

    intermediateEquation = bitLengthOfKey * log(2)

    estimatedStrength = ceil(1.923 * (intermediateEquation ** (1/3)) *
                         (pow(log(intermediateEquation), 2) ** (1/3)) - 4.69) / log(2)

    return ceil(estimatedStrength)


# Prerequisite to Appendix B.6 below: Testing if a number is prime
# A simple, but perhaps-not-so-efficient-for-large-numbers test is used - testing all numbers less than the square root of the given number
def checkIfPrime(numberToTest: int) -> bool:

    if numberToTest <= 1:
        return False

    for possibleValue in range(2, int(sqrt(numberToTest)) + 1):
        if numberToTest % possibleValue == 0:
            return False

    return True


# Appendix B.6: Shawe-Taylor Random_Prime Routine
# For the optional return value, it will be set to 0 if not used by the user, otherwise, the generated value will be set
def shaweTaylorRandomPrimeRoutine(lengthOfPrime: int, inputSeed: int, hashFunction=hashlib.sha256) -> tuple[str, int, int, int]:
    """
    Following FIPS 186-5 Appendix B.6, this function constructs a provable prime number using a hash function. This function is utilized by the `provablePrimeConstruction()` function. The default hash function is `SHA-256`, though a user can set one that they'd want to use.

    Naming for the variables -  (as named here) : (as named in the standard)
    `lengthOfPrime:  length`
    `inputSeed:      input_seed`
    """
    
    if lengthOfPrime < 2:
        return FAILURE, 0, 0, 0
    
    # primeSeed, primeGeneratorCounter, and pseudorandom are called 'prime_seed', 'prime_gen_counter', and 'c' respectively.
    # We intialize pseudorandom here because it is used in both branches of our if..else statement
    primeSeed = inputSeed

    initializedHash = hashFunction()
    hashLength = initializedHash.digest_size * 8

    # This branch handles steps 3-13 of the routine as described in the standard (i.e., where lengthOfPrime < 33)
    if lengthOfPrime < 33:

        primeSeed = inputSeed
        primeGeneratorCounter = 0

        # Step 13 dictates a loop be established (steps 5-12 are a loop), so we'll create a while loop which will be broken by the return statements in the loop
        while True:
            
            # Steps 5-7 generate a pseudorandom integer c with a bit length of the lengthOfPrime passed to the function; in our program, we will call 'c' as pseudorandom
            hashToUse = hashFunction()
            secondHashToUse = hashFunction()
            byteLength = ceil(primeSeed.bit_length() / 8) + 1

            hashToUse.update(primeSeed.to_bytes(length=byteLength))
            firstHashDigest = hashToUse.digest()
            secondHashToUse.update((primeSeed + 1).to_bytes(length=byteLength))
            secondHashDigest = secondHashToUse.digest()

            bytesForPseudorandom = bytes(a ^ b for a, b in zip(firstHashDigest, secondHashDigest, strict=True))
            pseudorandomHere = int().from_bytes(bytesForPseudorandom)
            pseudorandomHere = pow(2, (lengthOfPrime - 1)) + pow(pseudorandomHere, 1, pow(2, (lengthOfPrime - 1)))
            
            pseudorandomHere = (2 * floor(pseudorandomHere / 2)) + 1

            primeGeneratorCounter += 1
            primeSeed += 2

            # Step 10 - primality test on the value pseudorandom; technically, it is pseudorandom
            pseudorandomIsPrime = checkIfPrime(pseudorandomHere)
            
            # Step 11 - returning our prime number
            if pseudorandomIsPrime == True:
                return SUCCESS, pseudorandomHere, primeSeed, primeGeneratorCounter
            
            if primeGeneratorCounter > (4 * lengthOfPrime):
                return FAILURE, 0, 0, 0
    
    # This branch will handle what comes from step 14 onward
    if lengthOfPrime >= 33:
        # Steps 14-15
        functionStatus, pseudorandomC0, primeSeed, primeGeneratorCounter = shaweTaylorRandomPrimeRoutine((ceil(lengthOfPrime / 2) + 1), inputSeed)
        if functionStatus == FAILURE:
            return FAILURE, 0, 0, 0
        # Whilst this is not in the standard per se, its purpose is to make the above condition be satisfied once we get a correct value, since otherwise the function will enter the while loop and continue until we get a failure.
        if functionStatus == SUCCESS:
            return functionStatus, pseudorandomC0, primeSeed, primeGeneratorCounter
        
        # Steps 16-17
        iterations = ceil(lengthOfPrime / hashLength) - 1
        oldCounter = primeGeneratorCounter

        # Steps 18-21: Generate a pseudorandom integer x in the interval [2 ** (length – 1), 2 ** length]
        pseudorandomX = 0
        for iteration in range(0, iterations):
            newHash = hashFunction()
            byteStringLength = ceil(primeSeed.bit_length() / 8) + 1
            newHash.update((primeSeed + iteration).to_bytes(length=byteStringLength))
            digestedValue = int().from_bytes(newHash.digest())
            pseudorandomX += (digestedValue * pow(2, (iteration * hashLength)))

        primeSeed += iterations + 1
        pseudorandomX = pow(2, (lengthOfPrime - 1)) + pow(pseudorandomX, 1, pow(2, (lengthOfPrime - 1)))
        
        # Steps 22-25: generate a candidate prime c in the interval [2 ** (length – 1), 2 ** length]
        temporaryValue = ceil(pseudorandomX / (2 * pseudorandomC0))

        # Step 34 dictates a loop be established (steps 23-33 are a loop), so we'll create a while loop which will be broken by the return statements in the loop
        while True:

            if (2 * temporaryValue * pseudorandomC0 + 1) > pow(2, lengthOfPrime):
                temporaryValue = ceil( pow(2, (lengthOfPrime - 1)) / (2 * pseudorandomC0) )
            candidateC = 2 * temporaryValue * pseudorandomC0 + 1
            primeGeneratorCounter += 1

            # Steps 26-33: Testing the number pseudorandom (c) for primality
            a = 0
            for iteration in range(0, iterations):
                newHash = hashFunction()
                byteStringLength = ceil(primeSeed.bit_length() / 8) + 1
                newHash.update((primeSeed + iteration).to_bytes(length=byteStringLength))
                digestedValue = int().from_bytes(newHash.digest())
                a += ( digestedValue * pow(2, (iteration * hashLength)) )
            
            primeSeed += iterations + 1

            a = 2 + (a % (candidateC - 3))
            z = pow(a, (2 * temporaryValue), candidateC)

            if gcd((z-1), candidateC) == 1 and (pow(z, pseudorandomC0, candidateC) == 1):
                primeToReturnHere = candidateC
                return SUCCESS, primeToReturnHere, primeSeed, primeGeneratorCounter
            
            # Thus far, all loops end here
            if primeGeneratorCounter >= ((4 * lengthOfPrime) + oldCounter):
                return FAILURE, 0, 0, 0
            
            temporaryValue += 1


# Checking if P1 and P2 as used by the provablePrimeConstruction() function are acceptable, based on the requirements defined in table A.1 of Appendix A.1.1
def isAnAcceptableValue(modulusBitLength: int, bitLengthForP1: int, bitLengthForP2: int) -> bool:
    if modulusBitLength in range(2048, 3072):
        suitableMinLength = bitLengthForP1 > 140 and bitLengthForP2 > 140
        suitableMaxLength = (bitLengthForP1 + bitLengthForP2) <= 494
        if suitableMinLength and suitableMaxLength:
            return True
        else:
            return False
    elif modulusBitLength in range(3072, 4096):
        suitableMinLength = bitLengthForP1 > 170 and bitLengthForP2 > 170
        suitableMaxLength = (bitLengthForP1 + bitLengthForP2) <= 750
        if suitableMinLength and suitableMaxLength:
            return True
        else:
            return False
    elif modulusBitLength >= 4096:
        suitableMinLength = bitLengthForP1 > 200 and bitLengthForP2 > 200
        suitableMaxLength = (bitLengthForP1 + bitLengthForP2) <= 1005
        if suitableMinLength and suitableMaxLength:
            return True
        else:
            return False
    else:
        return False

# Euclidean's Extended Algorithm for calculating GCD
def calculateGCD(firstNumber: int, secondNumber: int):
    if firstNumber == 0:
        return secondNumber, 0, 1
    else:
        gcdObtained, x, y = calculateGCD(secondNumber % firstNumber, firstNumber)
        return gcdObtained, y - (secondNumber // firstNumber) * x, x

# We use this to find the modular inverse of our number; it relies on GCD that used the Extended Euclidean Algorithm
def calculateModularInverse(valueToInvert: int, modulus: int) -> int:
    gcdObtained, possibleInverse, _ = calculateGCD(valueToInvert, modulus)
    if gcdObtained != 1:
        raise Exception("Modular inverse does not exist")
    else:
        return possibleInverse % modulus


# We use this to calculate Step 14 of the provablePrimeConstruction() function
def findInverseValue(p0, p1, p2):
    # Calculate (p1 - 1) mod p2
    p1_minus_1 = (p1 - 1) % p2
    
    # Calculate (p0 * (p1 - 1)) mod p2
    product = (p0 * p1_minus_1) % p2
    
    try:
        # Find the modular multiplicative inverse
        inverseToReturn = calculateModularInverse(product, p2)
        
        # Ensure y is in the interval [1, p2]
        inverseToReturn = (inverseToReturn - 1) % p2 + 1
        return inverseToReturn
    
    except Exception:
        return None  # No solution exists


# Appendix B.10: Construct a Provable Prime (Possibly with Conditions) Based on Contemporaneously Constructed Auxiliary Provable Primes
# The auxiliary primes are set to be 224 bits long by default
def provablePrimeConstruction(requestedBitLength: int, firstSeedToUse: int, publicExponent: int, bitLengthForP1=224, bitLengthForP2=224, hashFunction = hashlib.sha256) -> tuple[str, int, int, int, int]:
    """
    Following FIPS 186-5 Appendix B.10, this function generates a provable prime number. This is the function that we use to generate p and q, and is utilized by the generatePandQ() function

    Naming for the variables -  (as named here) : (as named in the standard)
    `requestedBitLength: L`
    `bitLengthForP1:     N1`
    `bitLengthForP2:     N2`
    `firstSeedToUse:     firstseed`
    `publicExponent:     e`
    """

    # Step 1: verify that bitLengthForP1, bitLengthForP2, and requestedBitLength * 2 are acceptable values per Appendix A.1.1
    areAcceptableValues = isAnAcceptableValue((requestedBitLength * 2), bitLengthForP1, bitLengthForP2)

    if areAcceptableValues is False:
        return FAILURE, 0, 0, 0, 0
    
    # Steps 2 & 3
    if bitLengthForP1 == 1:
        p1 = 1
        seedForP2 = firstSeedToUse
    if bitLengthForP1 >= 2:
        functionStatusForP1, p1, seedForP2, _ = shaweTaylorRandomPrimeRoutine(bitLengthForP1, firstSeedToUse)
        if functionStatusForP1 == FAILURE:
            return FAILURE, 0, 0, 0, 0
    
    # Steps 4 & 5
    if bitLengthForP2 == 1:
        p2 = 1
        seedForP0 = seedForP2
    if bitLengthForP2 >= 2:
        functionStatusForP2, p2, seedForP0, _ = shaweTaylorRandomPrimeRoutine(bitLengthForP2, seedForP2)
        if functionStatusForP2 == FAILURE:
            return FAILURE, 0, 0, 0, 0
    
    # Step 6
    requestedBitLengthForP0 = ceil(requestedBitLength / 2) + 1
    functionStatusForP0, p0, seedForP, _ = shaweTaylorRandomPrimeRoutine(requestedBitLengthForP0, seedForP0)
    if functionStatusForP0 == FAILURE:
        return FAILURE, 0, 0, 0, 0
    
    # Step 7
    if gcd((p0 * p1), p2) != 1:
        return FAILURE, 0, 0, 0, 0
    
    # Steps 8 & 9
    initializedHash = hashFunction()
    hashLength = initializedHash.digest_size * 8

    # In the standard, the two variables are labelled 'iterations' and 'pgen_counter' respectively
    iterationsForGenerationOfP = ceil(requestedBitLength / hashLength) - 1
    counterForGenerationOfP = 0

    # Steps 10-13: Generate pseudo-random x
    pseudorandomX = 0
    for iteration in range(0, iterationsForGenerationOfP):
        newHash = hashFunction()
        valueToDigest = seedForP + iteration
        byteLength = ceil(valueToDigest.bit_length() / 8) + 1
        newHash.update(valueToDigest.to_bytes(length=byteLength, byteorder='big'))
        digestedValue = int().from_bytes(newHash.digest())
        pseudorandomX += (digestedValue * pow(2, (iteration * hashLength)))
    
    seedForP += iterationsForGenerationOfP + 1

    calculationForX = floor( Decimal(sqrt(2)) * pow(2, (requestedBitLength - 1)) )
    pseudorandomX = calculationForX + pow(pseudorandomX, 1, ( pow(2, requestedBitLength) - calculationForX ))

    # Step 14: Generate candidate prime for p; inverseValue is called 'y' in the standard
    inverseValue = findInverseValue(p0, p1, p2)
    if inverseValue is None:
        return FAILURE, 0, 0, 0, 0
    
    # Step 15
    calculationForTemporaryValueT = ((2 * inverseValue * p0 * p1) + pseudorandomX)
    # temporaryValue is called 't' in the standard; the + 1 is meant to push the number up to its ceiling, since the regular division (/) operator was causing an error
    temporaryValue = (calculationForTemporaryValueT // (2 * p0 * p1 * p2)) + 1

    # Step 22 dictates a loop be established, so we'll create a while loop which will be broken by the return statements in the loop
    while True:
        # Step 16
        # I have separated the calculation for testValue so that the condition for the if block is readable
        testValue = 2 * (temporaryValue * (p2 - inverseValue)) * p0 * (p1 + 1)
        if testValue > pow(2, requestedBitLength):
            temporaryValue = ceil( ( (2 * inverseValue * p0 * p1) + floor( sqrt(2) * pow(2, (requestedBitLength - 1) ) ) ) / (2 * p0 * p1 * p2) )
        
        # Step 17; the standard calls this value 'p'; p satisfies 0 = (p–1) mod (2 * p0 * p1) and 0 = (p+1) mod p2
        possiblePrime = (2 * temporaryValue * (p2 - inverseValue)) * p0 * p1 + 1
        # Step 18
        counterForGenerationOfP += 1

        # Step 19
        if gcd((possiblePrime - 1), publicExponent) == 1:
            a = 0
            for iteration in range(0, iterationsForGenerationOfP + 1):
                anotherHash = hashFunction()
                byteStringLength = ceil(valueToDigest.bit_length() / 8) + 1
                valueToDigest = seedForP + iteration
                anotherHash.update(valueToDigest.to_bytes(length=byteStringLength))
                digestedValue = int().from_bytes(anotherHash.digest())
                a += digestedValue * pow(2, (iteration * hashLength))
            seedForP = seedForP + iterationsForGenerationOfP + 1
            
            # Steps 19.4 - 19.6 
            a = 2 + (a % (possiblePrime - 3))
            exponentForZ = ((2 * temporaryValue * (p2 - inverseValue)) * p1)
            z = pow(a, exponentForZ, possiblePrime)
            
            if gcd((z - 1), possiblePrime) == 1 and (pow(z, p0, possiblePrime) == 1):
                return SUCCESS, possiblePrime, p1, p2, seedForP
        
        # Step 20 - I was tripping up at this point because of only using > and not >=; 1211hrs, 07/18th/2024
        if counterForGenerationOfP >= 5 * requestedBitLength:
            return FAILURE, 0, 0, 0, 0
        
        # Step 21
        temporaryValue += 1


# Appendix A.1.2: Generation of Random Primes that are Provably Prime
# Appendix A.1.2.1: Get the Seed
def generateSeedForPrimesGeneration(modulusBitLength: int) -> tuple[str, int]:
    """
    Following FIPS 186-5 Appendix A.1.2.1, this function generates a seed value needed by the `generatePandQ()` function. It takes the expected bit length of the modulus, `nlen` (here called `modulusBitLength`), and generates a seed value.
    
    If the value of `modulusBitLength` is odd, or is below 2048, the function returns `(FAILURE, 0)`; otherwise, it returns the expected seed inside the tuple `(SUCCESS, seed)`
    """

    # These conditions are taken from Section 5.1: our intended modulus length has to be odd, and greater than or equal to 2048
    if modulusBitLength % 2 != 0 or modulusBitLength < 2048:
        return FAILURE, 0
    
    if SECURITY_STRENGTHS.get(modulusBitLength) is None:
        securityStrength = calculateSecurityStrength(modulusBitLength)
    else:
        securityStrength = SECURITY_STRENGTHS.get(modulusBitLength)

    seed = randbits((2 * securityStrength))

    # Without this loop, this function fails intermittently as the seed's bit length ends up being less that (2 * securityStrength). This loop guarantees that we will always get a seed that meets the condition stipulated.
    while seed.bit_length() < (2 * securityStrength):
        seed = randbits((2 * securityStrength))

    return SUCCESS, seed

# Appendix A.1.2.2: Construction of the Provable Primes p and q
def generatePandQ(modulusBitLength: int, seed: int, publicExponent=65537) -> tuple[str, tuple[int, int]]:
    """
    Following FIPS 186-5 Appendix A.1.2.2, this function generates `p` and `q`, the primes needed to construct our modulus `n`. The default value of the public exponent is `65537`
    
    It takes the intended bit length of the modulus, `nlen` (here called `modulusBitLength`), the public exponent `e`, and the seed that we generate using the `generateSeedForPrimesGeneration()` function. It returns a triple of either `(FAILURE, 0, 0)` if it encounters a failure, or `(SUCCESS, p, q)` if successful.
    """
    # Step 1
    if modulusBitLength < 2048:
        return FAILURE, 0, 0
    
    # Step 2 - any number that fails to meet these criteria will lead to a failure
    exponentNotWithinBounds = (publicExponent <= (1 << 16)) or (publicExponent >= (1 << 256))
    if exponentNotWithinBounds or (publicExponent % 2 == 0):
        return FAILURE, 0, 0
    
    # Step 3 - get the value for security strength that matches the modulusBitLength we have supplied; either calculate or fetch from the dictionary SECURITY_STRENGTHS
    if SECURITY_STRENGTHS.get(modulusBitLength) is not None:
        securityStrength = SECURITY_STRENGTHS[modulusBitLength]

    if SECURITY_STRENGTHS.get(modulusBitLength) is None:
        securityStrength = calculateSecurityStrength(modulusBitLength)

    # Step 4
    if seed.bit_length() < (2 * securityStrength):
        return FAILURE, 0, 0
    
    # Step 5
    workingSeed = seed

    # Step 6 - generating p
    # firstPrime contains the value for p, the first prime number we need in order to calculate our modulus n
    # It is p, as picked from firstPrime, that is the first of the two primes returned to the user
    firstPrime = provablePrimeConstruction((modulusBitLength // 2), workingSeed, publicExponent)
    if firstPrime[0] == FAILURE:
        return FAILURE, 0, 0
    else:
        _, p, _, _, seedFromFirstPrime = firstPrime
        workingSeed = seedFromFirstPrime

    # Step 7
    # Initializing q so that we can be able to perform the while loop below
    secondPrime = provablePrimeConstruction((modulusBitLength // 2), seedFromFirstPrime, publicExponent)
    if secondPrime[0] == FAILURE:
        return FAILURE, 0, 0
    else:
        _, possibleQ, _, _, seedFromSecondPrime = secondPrime
        workingSeed = seedFromSecondPrime
        q = possibleQ

    # This condition is step 8 in the steps listed in the Appendix. It needs to run at least once for us to get a value of q.
    # Inside the loop is step 7 in the steps listed in the Appendix
    while abs(p - q) <= pow(2, (int(modulusBitLength / 2) - 100)):

        secondPrime = provablePrimeConstruction((modulusBitLength // 2), seedFromFirstPrime, publicExponent)
        if secondPrime[0] == FAILURE:
            return FAILURE, 0, 0
        else:
            _, possibleQ, _, _, seedFromSecondPrime = secondPrime
            workingSeed = seedFromSecondPrime
            q = possibleQ
    
    # Zeroise internally generated seeds
    workingSeed = 0
    seedFromFirstPrime = 0
    seedFromSecondPrime = 0

    return SUCCESS, p, q


# Generating n, our modulus, as well as d, our private exponent
# This implements part of the criteria specified in Apendix A.1.1
def generateKeyMaterial(modulusBitLength: int, tupleWithPandQ: tuple[int, int], publicExponent=65537) -> tuple[int, int, int, int, int]:
    """
    This function takes in our modulus length (in bits), as well as the prime factors p and q - presumably taken from generatePandQ - and generates d, our private exponent
    """
    p, q = tupleWithPandQ

    totientOfModulus = lcm((p - 1), (q - 1))

    possiblePrivateExponent = calculateModularInverse(publicExponent, totientOfModulus)
    
    firstConditionToMeet = pow(2, (modulusBitLength // 2)) < possiblePrivateExponent < totientOfModulus
    secondConditionToMeet = ((possiblePrivateExponent * publicExponent) % totientOfModulus) == 1

    if firstConditionToMeet and secondConditionToMeet:
        
        modulus = p * q
        return modulus, publicExponent, possiblePrivateExponent, p, q

if __name__ == '__main__':
    print("Testing bed.")

    # Testing the possible key sizes:
        # 3072 bits
    # status, mySeed = generateSeedForPrimesGeneration(3072)
    # print(status)
    # results = generatePandQ(3072, mySeed)
    # print(results)

        # 2048 bits
    # status1, mySeed1 = generateSeedForPrimesGeneration(2048)
    # print(status1)
    # results1 = generatePandQ(2048, mySeed1)
    # print(results1)
    
        # 4096 bits
    # status2, mySeed2 = generateSeedForPrimesGeneration(4096)
    # print(status2)
    # results2 = generatePandQ(4096, mySeed2)
    # print(results2)

        # Generating the full key
    modulusToUse = 2048
    _, initialSeed = generateSeedForPrimesGeneration(modulusToUse)
    _, p, q = generatePandQ(modulusToUse, initialSeed)
    n1, n2, n3, n4, n5 = generateKeyMaterial(modulusToUse, (p, q))
    print((n1, n2, n3, n4, n5))

    # b = 8192
    # a = generateSeedForPrimesGeneration(b)
    # _, initialSeed = generateSeedForPrimesGeneration(b)
    # _, p, q = generatePandQ(b, initialSeed)
    # n6, n7, n8, n9, n10 = generateKeyMaterial(b, (p, q))
    # print(n6)
    # print(n7)
    # print(n8)
    # print(n9)
    # print(n10)
