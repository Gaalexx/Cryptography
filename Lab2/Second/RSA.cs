using System;
using System.Numerics;
using MathNet.Numerics.Random;

namespace Program
{
    enum SimplicityTestType
    {
        Ferma,
        SolovayStrassen,
        MillerRabin,
    }

    interface IKeyGenerator
    {
        public (BigInteger, BigInteger) generateKeyPair();
    }

    class RSAKeyGenerator : IKeyGenerator
    {
        private readonly SimplicityTestAbstract simplicityTest;
        private readonly double probability;
        private readonly int bitLen;

        private bool tryFermaAttack(BigInteger p, BigInteger q, int maxIterations = 100000)
        {
            BigInteger n = p * q;

            if (p == q)
            {
                return true;
            }

            BigInteger A = CryptographicMath.Sqrt(n);
            if (A * A < n)
            {
                A++;
            }

            BigInteger maxA = (p + q) / 2;
            BigInteger minA = A;

            for (int i = 0; i < maxIterations; i++)
            {
                BigInteger x = A * A - n;

                if (x < 0)
                {
                    A++;
                    continue;
                }

                BigInteger B = CryptographicMath.Sqrt(x);

                if (B * B == x)
                {
                    if (A - B == p && A + B == q)
                    {
                        return true;
                    }
                    if (A - B == q && A + B == p)
                    {
                        return true;
                    }
                    break;
                }

                A++;

                if (A > maxA + 1000)
                {
                    break;
                }
            }

            return false;
        }

        //private bool tryVienerAttack(BigInteger)

        public RSAKeyGenerator(
            SimplicityTestType simplicityTestType,
            double probability,
            int bitLen
        )
        {
            switch (simplicityTestType)
            {
                case SimplicityTestType.Ferma:
                {
                    this.simplicityTest = new FermaTest();
                    break;
                }
                case SimplicityTestType.SolovayStrassen:
                {
                    this.simplicityTest = new SolovayStrassenTest();
                    break;
                }
                case SimplicityTestType.MillerRabin:
                {
                    this.simplicityTest = new MillerRabinTest();
                    break;
                }
                default:
                {
                    throw new Exception("Invalid simplicity test type");
                }
            }
            if (probability < 0.5 || probability >= 1)
            {
                throw new Exception("The probability must be in range of [0.5; 1.0)");
            }
            this.probability = probability;
            this.bitLen = bitLen;
        }

        public BigInteger getPrime()
        {
            BigInteger prime;
            Random random = new Random();
            int byteCount = (this.bitLen + 7) / 8;
            byte[] bytes = new byte[byteCount];

            do
            {
                random.NextBytes(bytes);

                bytes[byteCount - 1] |= 0x80;

                bytes[0] |= 0x01;

                prime = new BigInteger(bytes, isUnsigned: true);
            } while (!this.simplicityTest.Test(prime, this.probability));

            return prime;
        }

        public (BigInteger, BigInteger) generateKeyPair()
        {
            var res = (this.getPrime(), this.getPrime());
            while (!tryFermaAttack(res.Item1, res.Item2))
            {
                res = (this.getPrime(), this.getPrime());
            }
            //тут сделать проверки на атаки
            return res;
        }
    }

    class RSA
    {
        private readonly RSAKeyGenerator keyGenerator;
        private BigInteger p,
            q,
            n,
            e,
            d;

        private BigInteger getExponent(BigInteger fi)
        {
            BigInteger e = keyGenerator.getPrime(); // = 65537;

            while (CryptographicMath.EuclideanAlgorithm(e, fi) != 1)
            {
                e = keyGenerator.getPrime();
            }
            return e;
        }

        public RSA(SimplicityTestType simplicityTestType, double probability, int bitLen)
        {
            this.keyGenerator = new RSAKeyGenerator(simplicityTestType, probability, bitLen);
            (p, q) = this.keyGenerator.generateKeyPair();
            n = p * q;
            BigInteger fi = (p - 1) * (q - 1);
            e = getExponent(fi); //65537; //getExponent(fi);
            var res = CryptographicMath.ExtendedEuclideanAlgorithm(e, fi);
            d = res.Item2 < 0 ? res.Item2 + fi : res.Item2;

            Console.WriteLine($"p = {p}");
            Console.WriteLine($"q = {q}");
            Console.WriteLine($"n = {n}");
            Console.WriteLine($"e = {e}");
            Console.WriteLine($"d = {d}");
        }

        public BigInteger encrypt(BigInteger message)
        {
            return CryptographicMath.ModularExponentiation(message, e, n);
        }

        public BigInteger decrypt(BigInteger cipherText)
        {
            return CryptographicMath.ModularExponentiation(cipherText, d, n);
        }
    }
}
