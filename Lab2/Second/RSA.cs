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
        public (BigInteger, BigInteger, BigInteger, BigInteger) generateKeys();
    }

    class RSAKeyGenerator : IKeyGenerator
    {
        private readonly SimplicityTestAbstract simplicityTest;
        private readonly double probability;
        private readonly int bitLen;

        private bool tryFermaAttack(BigInteger p, BigInteger q, int maxIterations = 3)
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

        private bool tryVienerAttack(BigInteger e, BigInteger n)
        {
            var cf = CryptographicMath.ContinuedFraction(e, n);
            var convergents = CryptographicMath.GetConvergents(cf);

            foreach (var (k, d) in convergents)
            {
                if (k == 0 || d <= 0)
                {
                    continue;
                }

                BigInteger edMinus1 = e * d - 1;
                if (edMinus1 % k != 0)
                {
                    continue;
                }

                BigInteger phi = edMinus1 / k;
                BigInteger sum = n - phi + 1;
                BigInteger discriminant = sum * sum - 4 * n;

                if (discriminant < 0)
                {
                    continue;
                }

                BigInteger sqrtD = CryptographicMath.Sqrt(discriminant);
                if (sqrtD * sqrtD != discriminant)
                {
                    continue;
                }

                BigInteger p = (sum + sqrtD) / 2;
                BigInteger q = (sum - sqrtD) / 2;

                if (p * q == n && p > 1 && q > 1)
                {
                    return true;
                }
            }
            return false;
        }

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

        /* public BigInteger getPrime()
        {
            BigInteger prime;
            Random random = new Random();
            int byteCount = (this.bitLen + 7) / 8;
            byte[] bytes = new byte[byteCount];

            do
            {
                random.NextBytes(bytes);

                //bytes[byteCount - 1] |= 0x80;

                bytes[0] |= 0x01;

                prime = new BigInteger(bytes, isUnsigned: true);
            } while (!this.simplicityTest.Test(prime, this.probability));

            return prime;
        } */

        private static readonly int[] SmallPrimes =
        {
            3,
            5,
            7,
            11,
            13,
            17,
            19,
            23,
            29,
            31,
            37,
            41,
            43,
            47,
            53,
            59,
            61,
            67,
            71,
            73,
            79,
            83,
            89,
            97,
        };

        /* public BigInteger getPrime()
        {
            Random random = new Random();
            int byteCount = (this.bitLen + 7) / 8;
            byte[] bytes = new byte[byteCount];
            bool divisible;
            while (true)
            {
                random.NextBytes(bytes);

                bytes[byteCount - 1] |= 0x80; // Старший бит = 1
                bytes[0] |= 0x01; // Младший бит = 1 (нечетное)

                BigInteger candidate = new BigInteger(bytes, isUnsigned: true);

                divisible = false;
                foreach (int prime in SmallPrimes)
                {
                    if (candidate % prime == 0 && candidate != prime)
                    {
                        divisible = true;
                        break;
                    }
                }

                if (divisible)
                    continue;

                if (this.simplicityTest.Test(candidate, this.probability))
                    return candidate;
            }
        } */

        public BigInteger getPrime()
        {
            BigInteger? result = null;
            object lockObj = new object();
            int threadCount = Environment.ProcessorCount;

            Parallel.For(
                0,
                threadCount,
                (i, state) =>
                {
                    Random random = new Random(Guid.NewGuid().GetHashCode());
                    int byteCount = (this.bitLen + 7) / 8;
                    byte[] bytes = new byte[byteCount];

                    while (!state.IsStopped)
                    {
                        random.NextBytes(bytes);
                        bytes[byteCount - 1] |= 0x80;
                        bytes[0] |= 0x01;

                        BigInteger candidate = new BigInteger(bytes, isUnsigned: true);

                        bool divisible = false;
                        foreach (int prime in SmallPrimes)
                        {
                            if (candidate % prime == 0 && candidate != prime)
                            {
                                divisible = true;
                                break;
                            }
                        }

                        if (divisible)
                            continue;

                        if (this.simplicityTest.Test(candidate, this.probability))
                        {
                            lock (lockObj)
                            {
                                if (result == null)
                                {
                                    result = candidate;
                                    state.Stop();
                                }
                            }
                            break;
                        }
                    }
                }
            );

            return result!.Value;
        }

        private BigInteger getExponent(BigInteger fi)
        {
            BigInteger e = getPrime(); // = 65537;

            while (CryptographicMath.EuclideanAlgorithm(e, fi) != 1)
            {
                e = getPrime();
            }
            return e;
        }

        public (BigInteger, BigInteger, BigInteger, BigInteger) generateKeys()
        {
            BigInteger p = this.getPrime(),
                q = this.getPrime();

            /* while (tryFermaAttack(p, q))
            {
                p = this.getPrime();
                q = this.getPrime();
                Console.WriteLine($"Q = {q}");
                Console.WriteLine($"P = {p}");
                Console.WriteLine("____________________");
            } */
            BigInteger fi = (p - 1) * (q - 1);
            BigInteger e = getExponent(fi);
            BigInteger n = p * q;

            /* while (tryVienerAttack(e, n))
            {
                e = getExponent(fi);
                Console.WriteLine($"E = {e}");
                Console.WriteLine("____________________");
            } */

            var res = CryptographicMath.ExtendedEuclideanAlgorithm(e, fi);
            BigInteger d = res.Item2 < 0 ? res.Item2 + fi : res.Item2;
            return (p, q, e, d);
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

        public RSA(SimplicityTestType simplicityTestType, double probability, int bitLen)
        {
            this.keyGenerator = new RSAKeyGenerator(simplicityTestType, probability, bitLen);
            (p, q, e, d) = this.keyGenerator.generateKeys();
            n = p * q;
            /* Console.WriteLine($"p = {p}");
            Console.WriteLine($"q = {q}");
            Console.WriteLine($"n = {n}");
            Console.WriteLine($"e = {e}");
            Console.WriteLine($"d = {d}"); */
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

    struct VienerAttackResults
    {
        public BigInteger d { get; set; }
        public BigInteger fi { get; set; }
        public List<Tuple<BigInteger, BigInteger>> factorialConvergents;

        public VienerAttackResults(
            BigInteger d,
            BigInteger fi,
            List<Tuple<BigInteger, BigInteger>> factorialConvergents
        )
        {
            this.d = d;
            this.fi = fi;
            this.factorialConvergents = factorialConvergents;
        }
    }

    class VienerAttack
    {
        private readonly BigInteger n;
        private readonly BigInteger e;

        public VienerAttack(BigInteger n, BigInteger e)
        {
            this.n = n;
            this.e = e;
        }

        public VienerAttackResults? attack()
        {
            var cf = CryptographicMath.ContinuedFraction(e, n);
            var convergents = CryptographicMath.GetConvergents(cf);
            List<Tuple<BigInteger, BigInteger>> fractions =
                new List<Tuple<BigInteger, BigInteger>>();
            int count = 0;
            BigInteger resD = 0,
                resFi = 0;
            foreach (var (k, d) in convergents)
            {
                if (k == 0 || d <= 0)
                {
                    continue;
                }

                BigInteger edMinus1 = e * d - 1;
                if (edMinus1 % k != 0)
                {
                    continue;
                }

                BigInteger phi = edMinus1 / k;
                BigInteger sum = n - phi + 1;
                BigInteger discriminant = sum * sum - 4 * n;

                if (discriminant < 0)
                {
                    continue;
                }

                BigInteger sqrtD = CryptographicMath.Sqrt(discriminant);
                if (sqrtD * sqrtD != discriminant)
                {
                    continue;
                }

                BigInteger p = (sum + sqrtD) / 2;
                BigInteger q = (sum - sqrtD) / 2;

                if (p * q == n && p > 1 && q > 1)
                {
                    count++;
                    resD = d;
                    resFi = (p - 1) * (q - 1);
                    fractions.Add(new Tuple<BigInteger, BigInteger>(k, d));
                }
            }
            if (count > 0)
            {
                return new VienerAttackResults(resD, resFi, fractions);
            }
            else
            {
                return null;
            }
        }
    }
}
