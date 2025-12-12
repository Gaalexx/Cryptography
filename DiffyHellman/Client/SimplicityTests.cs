using System.Numerics;
using MathNet.Numerics;
using MathNet.Numerics.Random;

namespace DiffyHellman
{
    interface ISimplicityTest
    {
        public abstract bool Test(BigInteger testValue, double minimalProbability);
        public abstract BigInteger GetIterationsCount(
            BigInteger testValue,
            double minimalProbability
        );
        public abstract bool PerformTest(BigInteger testValue, BigInteger iterations);
        public abstract bool Iteration(BigInteger testValue);
        public abstract double GetSingleTestErrorProbability();
    }

    abstract class SimplicityTestAbstract : ISimplicityTest
    {
        public virtual bool Test(BigInteger testValue, double minimalProbability)
        {
            if (testValue < 2)
            {
                throw new Exception("Test value must be greater than 1");
            }
            if (testValue == 2 || testValue == 3)
            {
                return true;
            }
            if (testValue % 2 == 0)
            {
                return false;
            }
            if (minimalProbability < 0.5 || minimalProbability > 1)
            {
                throw new Exception("Minimal probability must be in range of[0.5; 1]!");
            }

            BigInteger k = GetIterationsCount(testValue, minimalProbability);

            return PerformTest(testValue, k);
        }

        public virtual bool PerformTest(BigInteger testValue, BigInteger iterations)
        {
            var random = SystemRandomSource.Default;

            for (BigInteger i = 0; i < iterations; i++)
            {
                if (!Iteration(testValue))
                {
                    return false;
                }
            }
            return true;
        }

        public virtual BigInteger GetIterationsCount(
            BigInteger testValue,
            double minimalProbability
        )
        {
            double error = GetSingleTestErrorProbability();
            BigInteger k = (BigInteger)(
                Math.Ceiling(Math.Log(1 - minimalProbability) / Math.Log(error))
            );
            //Console.WriteLine($"k = {k}");
            return BigInteger.Min(k, 100);
        }

        public abstract bool Iteration(BigInteger testValue);
        public abstract double GetSingleTestErrorProbability();
    }

    class FermaTest : SimplicityTestAbstract
    {
        public override bool Iteration(BigInteger testValue)
        {
            var random = SystemRandomSource.Default;
            BigInteger randomValue = random.NextBigIntegerSequence(2, testValue - 2).First();
            if (CryptographicMath.EuclideanAlgorithm(randomValue, testValue) != 1)
            {
                return false;
            }
            return CryptographicMath.ModularExponentiation(randomValue, testValue - 1, testValue)
                == 1;
        }

        public override double GetSingleTestErrorProbability()
        {
            return 0.5;
        }
    }

    class SolovayStrassenTest : SimplicityTestAbstract
    {
        public override bool Iteration(BigInteger testValue)
        {
            var random = SystemRandomSource.Default;
            BigInteger a = random.NextBigIntegerSequence(2, testValue - 2).First();
            if (CryptographicMath.EuclideanAlgorithm(a, testValue) != 1)
            {
                return false;
            }
            BigInteger jacobi = CryptographicMath.YakobiSymbol(a, testValue);
            BigInteger mod = CryptographicMath.ModularExponentiation(
                a,
                (testValue - 1) / 2,
                testValue
            );
            return ((jacobi % testValue) + testValue) % testValue == mod;
        }

        public override double GetSingleTestErrorProbability()
        {
            return 0.5;
        }
    }

    class MillerRabinTest : SimplicityTestAbstract
    {
        public override bool Iteration(BigInteger testValue)
        {
            BigInteger d = testValue - 1,
                c = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                c++;
            }

            var random = SystemRandomSource.Default;
            BigInteger a = random.NextBigIntegerSequence(2, testValue - 2).First();
            BigInteger x = CryptographicMath.ModularExponentiation(a, d, testValue);

            if (x == 1 || x == testValue - 1)
            {
                return true;
            }

            for (BigInteger i = 0; i < c - 1; i++)
            {
                x = CryptographicMath.ModularExponentiation(x, 2, testValue);
                if (x == testValue - 1)
                {
                    return true;
                }
                if (x == 1)
                {
                    return false;
                }
            }

            return false;
        }

        public override double GetSingleTestErrorProbability()
        {
            return 0.25;
        }
    }

    class Primes
    {
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

        public static readonly SolovayStrassenTest solovayStrassen = new SolovayStrassenTest();
        public static readonly MillerRabinTest millerRabin = new MillerRabinTest();
        public static readonly FermaTest ferma = new FermaTest();

        public static BigInteger getPrime(
            int bitLen,
            ISimplicityTest? simplicityTest,
            double probability = 0.9999
        )
        {
            if (simplicityTest == null)
            {
                simplicityTest = millerRabin;
            }

            BigInteger? result = null;
            object lockObj = new object();
            int threadCount = Environment.ProcessorCount;

            Parallel.For(
                0,
                threadCount,
                (i, state) =>
                {
                    Random random = new Random(Guid.NewGuid().GetHashCode());
                    int byteCount = (bitLen + 7) / 8;
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

                        if (simplicityTest.Test(candidate, probability))
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
    }
}
