/*
  Generate RSA public and private key for use with SSH.
  ...
  First, run and save output to a file: ..key.asn1
  Run `openssl asn1parse -genconf ..key.asn1 -out key.der`
  Followed by `openssl rsa -in key.der -inform der -text -check -out id_rsa
  Then `ssh-keygen -y -f id_rsa > id_rsa.pub`
  To generate the private and public key files.
*/
#include <stdint.h>
#include <iostream>
#include <string>
#include <cmath>
#include <ctime>
#include <windows.h>
#include "BigIntegerLibrary.hh"

// Avoid any debug-related output including progress
#define NO_OUTPUT

// SSH RSA Private Key ASN.1
struct PRIVATE_KEY {
	int version;
	BigUnsigned modulus;
	BigUnsigned publicExponent;
	BigUnsigned privateExponent;
	BigUnsigned prime1;
	BigUnsigned prime2;
	BigUnsigned exponent1;
	BigUnsigned exponent2;
	BigUnsigned coefficient;
};

void PrintRSA(PRIVATE_KEY key) {
	std::cout << "asn1=SEQUENCE:rsa_key" << std::endl;
	std::cout << std::endl;
	std::cout << "[rsa_key]" << std::endl;
	std::cout << "version=INTEGER:0" << std::endl;
	std::cout << "modulus=INTEGER:" << key.modulus << std::endl;
	std::cout << "pubExp=INTEGER:" << key.publicExponent << std::endl;
	std::cout << "privExp=INTEGER:" << key.privateExponent << std::endl;
	std::cout << "p=INTEGER:" << key.prime1 << std::endl;
	std::cout << "q=INTEGER:" << key.prime2 << std::endl;
	std::cout << "e1=INTEGER:" << key.exponent1 << std::endl;
	std::cout << "e2=INTEGER:" << key.exponent2 << std::endl;
	std::cout << "coeff=INTEGER:" << key.coefficient << std::endl;

	std::cout << std::endl;
}

/* xorshift128+ */
uint64_t s128[ 2 ] = { 0xf917e2cf34dfb894, 0x35dd44d4b13a3021 };

uint64_t nextXOR128(void) { 
	uint64_t s1 = s128[ 0 ];
	const uint64_t s0 = s128[ 1 ];
	s128[ 0 ] = s0;
	s1 ^= s1 << 23; // a
	return ( s128[ 1 ] = ( s1 ^ s0 ^ ( s1 >> 17 ) ^ ( s0 >> 26 ) ) ) + s0; // b, c
}

/* xorshift1024*  */
uint64_t s1024[ 16 ] = 
{
	0x35936cc3bf59475b, 0xfc888076d16d05b1, 0x0f92fd658285b801, 0xea6a051307db2c20,
	0xfd8f8f1695e608bf, 0x5caec7aa09088e0e, 0xbd9faedfc2fc4809, 0xa742f679000a02ac,
	0xa877ce8775540ce4, 0x1d90fc24ade8e48f, 0x2b27326ce7c8ef32, 0x1abe36d737e887a6,
	0x6f3d22845135ab50, 0xbae850a0f24bb190, 0xec1f8a004a6cd5b2, 0x973043ca26d717f5,
};

uint64_t nextXOR1024(void) { 
	static int p = 2;
	uint64_t s0 = s1024[ p ];
	uint64_t s1 = s1024[ p = ( p + 1 ) & 15 ];
	s1 ^= s1 << 31; // a
	s1 ^= s1 >> 11; // b
	s0 ^= s0 >> 30; // c
	return ( s1024[ p ] = s0 ^ s1 ) * 1181783497276652981LL; 
}

// The seed for our random number generator.
void InitializeRandom()
{
	unsigned int q;
	srand((int)GetTickCount());
	s128[0] ^= (((unsigned long long int)time(0) << 32) | GetTickCount());
	s128[1] ^= ((unsigned long long int)rand() << 32) | (unsigned long long int)(rand());

	for (q = 0; q < 16; q++)
	{
		s1024[q] ^= nextXOR128();
	}

	srand((unsigned int)time(0) ^ GetTickCount());
}

// Our random function
unsigned long long int Random(unsigned long long int input)
{
	unsigned long long int storage = 0U;
	storage ^= input;
	storage ^= ((unsigned long long int)(rand()) << 32) 
		| (unsigned long long int)(rand());
	storage ^= nextXOR1024();
	storage ^= (nextXOR128() << 52) ^ (nextXOR128() << 28) ^ (nextXOR128());
	storage ^= GetTickCount();
	return storage;
}

// Generate numbers
BigUnsigned inline SuperRandomNumber(unsigned int required_bits);

// Key Generation
const unsigned int SMALL_PRIME_COUNT = 10840;
const unsigned int SMALL_PRIME_LIMIT = 114688;

BigUnsigned SmallPrimes[SMALL_PRIME_COUNT];

void InitSmallPrimes()
{
	unsigned int x, y, z;
	char numbers[SMALL_PRIME_LIMIT];

	/* calculate small prime numbers; first 300 or less than < 2000 */
	for (x = 0; x < SMALL_PRIME_LIMIT; x++)
		numbers[x] = 1;

	z = 0;
	for (x = 2; x < SMALL_PRIME_LIMIT && z < SMALL_PRIME_COUNT; x++)
	{
		if (numbers[x]) 
		{
			SmallPrimes[z] = BigUnsigned(x);
			z++;

			for (y = 1; x*y < SMALL_PRIME_LIMIT; y++)
			{
				numbers[x*y] = 0;
			}
		}
	}
}

// result = a^d mod n
inline BigUnsigned ModExp(BigUnsigned& a, BigUnsigned d, BigUnsigned& n)
{
	/* Chinese remainder theorem */
	BigUnsigned answer = 1;
	BigUnsigned exp = a;
	BigUnsigned denom = d;
	do
	{
		if ((denom % 2) == 1) {
			answer = (answer * exp) % n;
		}
		exp = (exp * exp) % n;
		denom = (denom / 2);
	} while (denom != 1);
	return (answer * exp) % n;
}

// Is a Prime less than 114688
const bool inline IsPrimeSmall(BigUnsigned& x)
{
	unsigned int z;
	for (z = 0; z < SMALL_PRIME_COUNT; z++)
	{
		if ((x % SmallPrimes[z]).isZero())
		{
			return false;
		}
	}
	return true;
}

// Use each of the small primes as a base
const bool ExtendedMRBPT(BigUnsigned& r)
{
	//if (!IsPrimeSmall(n)) return false;
	BigUnsigned r_minus_one = r - 1;
	BigUnsigned d = r_minus_one;
	BigUnsigned s = 1;
	while ((d % 2).isZero()) {
		s = s * 2;
		d = d / 2;
	}

	BigUnsigned sloop;
	for (unsigned int k = 0; k < SMALL_PRIME_COUNT; k++)
	{
		BigUnsigned a = SmallPrimes[k];
		a = (a % (r - 4)) + 2;
		BigUnsigned x = ModExp(a, d, r);
		if (x == 1 || x == r_minus_one) continue;

		sloop = s - 1;
		while (!sloop.isZero())
		{
			x = (x*x) % r;
			if (x == 1) return false;
			if (x == r_minus_one) break;
			sloop = sloop - 1;
		}
		if (sloop.isZero()) return false;
	}
	return true;
}

// Miller-Rabin prime test
const bool MRBPT(BigUnsigned& r, unsigned int bitsize, unsigned int iterations)
{
	//if (!IsPrimeSmall(n)) return false;
	BigUnsigned r_minus_one = r - 1;
	BigUnsigned d = r_minus_one;
	BigUnsigned s = 1;
	while ((d % 2).isZero()) {
		s = s * 2;
		d = d / 2;
	}

	BigUnsigned sloop;
	for (unsigned int k = 0; k < iterations; k++)
	{
		BigUnsigned a = SuperRandomNumber(bitsize + 2);
		a = (a % (r - 4)) + 2;
		BigUnsigned x = ModExp(a, d, r);
		if (x == 1 || x == r_minus_one) continue;

		sloop = s - 1;
		while (!sloop.isZero())
		{
			x = (x*x) % r;
			if (x == 1) return false;
			if (x == r_minus_one) break;
			sloop = sloop - 1;
		}
		if (sloop.isZero()) return false;
	}
	return true;
}

// Fermat prime test
const bool FermatLittle(BigUnsigned& n, unsigned int bitsize, unsigned int iterations)
{
	//if (!IsPrimeSmall(n)) return false;
	BigUnsigned n_minus = (n - 1);

	for (unsigned int k = 0; k < iterations; k++)
	{
		BigUnsigned a = 0;
		while (a == 0 || a == 1 || a == n)
		{
			a = SuperRandomNumber(bitsize + 2);
			a = (a % n);
		}

		BigUnsigned x;
		x = ModExp(a, n_minus, n);
		if (x != 1) return false;
	}

	return true;
}

// Not divisible by small primes, passes Fermat and Miller-Rabin prime tests
const bool IsPrime(BigUnsigned& x, unsigned int bitsize)
{
	if (!IsPrimeSmall(x)) {
		return false;
	}
	if (!MRBPT(x, bitsize, 1024)) {
		return false;
	}
	if (!FermatLittle(x, bitsize, 1024)) {
		return false;
	}
	/*if (!ExtendedMRBPT(x)) {
		return false;
	}*/
	return true;
}

char randomDigits[4096];

// Random number of sufficient size.
BigUnsigned inline SuperRandomNumber(unsigned int required_bits)
{
	unsigned int decimal_digits = (required_bits/3) + 1;
retry:
	unsigned int i;
	char* str = randomDigits;
	for (i = 0; i <= decimal_digits; i++)
	{
		str[i] = '0' + (Random(i) % 10);
	}
	str[i] = '\0';
	std::string s(str);
	BigUnsigned result1 = stringToBigInteger(s).getMagnitude();
	if (result1.bitLength() < required_bits) goto retry;
	result1 = result1 >> (result1.bitLength() - required_bits);
	return result1;
}

// Generate a large prime of specified bitsize.
BigUnsigned GeneratePrime(unsigned int required_bits, int& trials)
{
	BigUnsigned number;
	trials = 0;

	do {
		trials++;
#ifndef NO_OUTPUT
		std::cout << ".";
#endif
		
		// loop until a prime number of sufficient size is found
		number = SuperRandomNumber(required_bits);
		if ((number % 2).isZero()) number++;
		if ((number % 3).isZero()) number = number + 2;
		if ((number % 5).isZero()) number = number + 4;
	} while (!IsPrime(number, required_bits));

#ifndef NO_OUTPUT
	std::cout << std::endl;
#endif
	return number;
}

// Greatest common divisor
BigUnsigned GCD(BigUnsigned a, BigUnsigned b)
{
	while (b != 0)
	{
		BigUnsigned temp;
		temp = b;
		b = (a % b);
		a = temp;
	}
	return a;
}

// Generate a public key (e)
BigUnsigned FindPublicKeyExponent(BigUnsigned totient, int bits)
{
	BigUnsigned number = SuperRandomNumber(bits);
	number = number % totient;

	while (true)
	{
		if (GCD(number, totient) == 1)
		{
			return number;
		}
		number = number + 1;
	}

	return BigUnsigned(0);
}

// Find the mod inverse of a number. [a^-1 (mod n)]
BigUnsigned ModInverse(BigUnsigned a, BigUnsigned n)
{
	BigInteger t = 0;
	BigInteger newt = 1;
	BigInteger r = n;
	BigInteger newr = a;

	BigInteger t1, r1;
	while (newr != 0)
	{
		BigInteger quotient = (r / newr);
		t1 = newt;
		newt = t - (quotient * newt);
		t = t1;
		r1 = newr;
		newr = r - quotient * newr;
		r = r1;
	}
	if (r > 1) { return BigUnsigned(0); }
	if (t < 0) { t = t + n; }


	return t.getMagnitude();
}


int main()
{
	PRIVATE_KEY key;
	BigUnsigned primeA;
	BigUnsigned primeB;
	BigUnsigned totient;

  // The size of the key to generate. The resulting key will be either size KEY_SIZE or KEY_SIZE+1.
	const int KEY_SIZE = 2048;
	const int KEY_SIZE_2 = KEY_SIZE / 2;

	InitSmallPrimes();
	InitializeRandom();

	{	// Generate two very large prime numbers. 
		int numAttempts;
		primeA = GeneratePrime(KEY_SIZE_2+1, numAttempts);
#ifndef NO_OUTPUT
		//std::cout << std::endl << std::endl << "Generated prime " << primeA << " in " << numAttempts << (numAttempts == 1 ? " try." : " tries.") << std::endl << std::endl;
		std::cout << "Prime 1 has " << primeA.bitLength() << " bits, ";
#endif
		primeB = GeneratePrime(KEY_SIZE_2, numAttempts);
#ifndef NO_OUTPUT
		//std::cout << std::endl << std::endl << "Generated prime " << primeB << " in " << numAttempts << (numAttempts == 1 ? " try." : " tries.") << std::endl << std::endl;
		std::cout << "Prime 2 has " << primeB.bitLength() << " bits, and ";
#endif

		if (primeB < primeA)
		{
			key.prime1 = primeA;
			key.prime2 = primeB;
		} else {
			key.prime1 = primeB;
			key.prime2 = primeA;
		}
	}

	key.modulus = key.prime1 * key.prime2;

#ifndef NO_OUTPUT
	std::cout << "Modulus has " << key.modulus.bitLength() << " bits.";
	std::cout << std::endl << std::endl;
#endif

	/* continuing on */
	totient = (key.prime1 - 1) * (key.prime2 - 1);

	do {
		key.publicExponent = FindPublicKeyExponent(totient, 8);
		key.privateExponent = ModInverse(key.publicExponent, totient); // decryption exponent

		if (key.privateExponent == 0) { std::cout << "Not invertible" << std::endl << std::endl; }

	} while (key.privateExponent == 0);

	key.exponent1 = key.privateExponent % (key.prime1 - 1);
	key.exponent2 = key.privateExponent % (key.prime2 - 1);
	key.coefficient = ModInverse(key.prime2, key.prime1);
	if (key.exponent1 == 0 || key.exponent2 == 0 || key.coefficient == 0) 
	{ 
		std::cout << "Error with exponents/coefficient." << std::endl; 
		return 1; 
	}

	PrintRSA(key);
#ifndef NO_OUTPUT
	std::cout << std::endl << std::endl << "Done." << std::endl;
	//system("PAUSE");
#endif
	return 0;
}

