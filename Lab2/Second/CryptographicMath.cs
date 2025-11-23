using System.Numerics;

namespace Program
{
    class CryptographicMath
    {
        private static BigInteger RecursiveEuclidianAlgorithm(BigInteger a, BigInteger b)
        {
            if (a == 0)
            {
                return b;
            }
            else
            {
                return RecursiveEuclidianAlgorithm(b % a, a);
            }
        }

        public static bool isPrime(BigInteger n)
        {
            /* for (BigInteger i = 2; i <= BigInteger.; i++)
            {
                if (n % i == 0)
                {
                    return false;
                }
            } */
            //переделать под проверки (потом)
            return true;
        }

        public static BigInteger LezhandrSymbol(BigInteger a, BigInteger p)
        {
            if (!isPrime(p) || p == 2)
            {
                throw new Exception("p must be prime and not equal to 2");
            }
            if (a % p == 0)
            {
                return 0;
            }
            return YakobiSymbol(a, p);
        }

        private static BigInteger RecursiveYakobiStep(BigInteger a, BigInteger b, BigInteger r)
        {
            BigInteger t = 0;
            while (a % 2 == 0)
            {
                a /= 2;
                t++;
                if (b % 8 == 3 || b % 8 == 5)
                {
                    r = -r;
                }
            }
            if (a % 4 == 3 && b % 4 == 3)
            {
                r = -r;
            }
            BigInteger c = a;
            a = b % c;
            b = c;

            if (a == 0)
            {
                return r;
            }
            else
            {
                return RecursiveYakobiStep(a, b, r);
            }
        }

        public static BigInteger YakobiSymbol(BigInteger a, BigInteger b)
        {
            if (EuclideanAlgorithm(a, b) != 1)
            {
                return 0;
            }
            BigInteger r = 1;
            if (a < 0)
            {
                a = -a;
                if (b % 4 == 3)
                {
                    r = -r;
                }
            }
            return RecursiveYakobiStep(a, b, r);
        }

        public static BigInteger EuclideanAlgorithm(BigInteger a, BigInteger b)
        {
            return RecursiveEuclidianAlgorithm(a, b);
        }

        public static (BigInteger, BigInteger, BigInteger) ExtendedEuclideanAlgorithm(
            BigInteger a,
            BigInteger b
        )
        {
            if (a == 0)
            {
                return (b, 0, 1);
            }
            var res = ExtendedEuclideanAlgorithm(b % a, a);
            BigInteger gcd = res.Item1,
                x1 = res.Item2,
                y1 = res.Item3;
            return (gcd, y1 - (b / a) * x1, x1);
        }

        public static BigInteger ModularExponentiation(
            BigInteger a,
            BigInteger n,
            BigInteger module
        )
        {
            BigInteger res = 1;
            while (n > 0)
            {
                if ((n & 1) == 1)
                {
                    res = res * a % module;
                }
                a = (a * a) % module;
                n /= 2;
            }
            return res;
        }
    }
}
