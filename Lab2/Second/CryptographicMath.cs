using System.Collections.Generic;
using System.Numerics;

namespace Program
{
    class CryptographicMath
    {
        public enum AlgorithmWay
        {
            Iterational,
            Recursive,
        }

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

        private static BigInteger IterationalEuclidianAlgorithm(BigInteger a, BigInteger b)
        {
            while (a != 0)
            {
                BigInteger temp = a;
                a = b % a;
                b = temp;
            }
            return b;
        }

        public static BigInteger Sqrt(BigInteger n)
        {
            if (n < 0)
            {
                throw new ArgumentException(
                    "Квадратный корень определен только для неотрицательных чисел"
                );
            }

            if (n == 0 || n == 1)
            {
                return n;
            }

            BigInteger left = 1;
            BigInteger right = n;
            BigInteger result = 0;

            while (left <= right)
            {
                BigInteger mid = (left + right) / 2;

                BigInteger square = mid * mid;

                if (square == n)
                {
                    return mid;
                }

                if (square < n)
                {
                    left = mid + 1;
                    result = mid;
                }
                else
                {
                    right = mid - 1;
                }
            }

            return result;
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

        public static BigInteger EuclideanAlgorithm(
            BigInteger a,
            BigInteger b,
            AlgorithmWay algorithmWay = AlgorithmWay.Iterational
        )
        {
            switch (algorithmWay)
            {
                case AlgorithmWay.Iterational:
                    return IterationalEuclidianAlgorithm(a, b);
                case AlgorithmWay.Recursive:
                    return RecursiveEuclidianAlgorithm(a, b);
                default:
                    return IterationalEuclidianAlgorithm(a, b);
            }
        }

        private static (BigInteger, BigInteger, BigInteger) IterationalExtendedEuclideanAlgorithm(
            BigInteger a,
            BigInteger b
        )
        {
            BigInteger prevCoeffA = 1,
                currCoeffA = 0;
            BigInteger prevCoeffB = 0,
                currCoeffB = 1;

            while (a != 0)
            {
                BigInteger quotient = b / a;
                BigInteger remainder = b % a;

                BigInteger newCoeffA = prevCoeffA - quotient * currCoeffA;
                BigInteger newCoeffB = prevCoeffB - quotient * currCoeffB;

                b = a;
                a = remainder;

                prevCoeffA = currCoeffA;
                currCoeffA = newCoeffA;

                prevCoeffB = currCoeffB;
                currCoeffB = newCoeffB;
            }

            return (b, prevCoeffA, prevCoeffB);
        }

        private static (BigInteger, BigInteger, BigInteger) RecursiveExtendedEuclideanAlgorithm(
            BigInteger a,
            BigInteger b
        )
        {
            if (a == 0)
            {
                return (b, 0, 1);
            }
            var res = RecursiveExtendedEuclideanAlgorithm(b % a, a);
            BigInteger gcd = res.Item1,
                x1 = res.Item2,
                y1 = res.Item3;
            return (gcd, y1 - (b / a) * x1, x1);
        }

        public static (BigInteger, BigInteger, BigInteger) ExtendedEuclideanAlgorithm(
            BigInteger a,
            BigInteger b,
            AlgorithmWay algorithmWay = AlgorithmWay.Iterational
        )
        {
            switch (algorithmWay)
            {
                case AlgorithmWay.Iterational:
                    return IterationalExtendedEuclideanAlgorithm(a, b);
                case AlgorithmWay.Recursive:
                    return RecursiveExtendedEuclideanAlgorithm(a, b);
                default:
                    return IterationalExtendedEuclideanAlgorithm(a, b);
            }
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

        public static List<BigInteger> ContinuedFraction(BigInteger a, BigInteger b)
        {
            if (b == 0)
            {
                throw new ArgumentException("b can't be equal to 0");
            }
            if (a <= 0 || b <= 0)
            {
                throw new ArgumentException("a and b must be positive");
            }

            List<BigInteger> result = new List<BigInteger>();
            while (b != 0)
            {
                BigInteger q = a / b;
                result.Add(q);
                BigInteger temp = b;
                b = a - q * b;
                a = temp;
            }
            return result;
        }

        public static List<(BigInteger, BigInteger)> GetConvergents(List<BigInteger> cf)
        {
            List<(BigInteger, BigInteger)> convergents = new List<(BigInteger, BigInteger)>();
            if (cf.Count == 0)
            {
                return convergents;
            }

            BigInteger p_prev = 1,
                p_curr = cf[0];
            BigInteger q_prev = 0,
                q_curr = 1;
            convergents.Add((p_curr, q_curr));

            for (int i = 1; i < cf.Count; i++)
            {
                BigInteger p_next = cf[i] * p_curr + p_prev;
                BigInteger q_next = cf[i] * q_curr + q_prev;
                convergents.Add((p_next, q_next));
                p_prev = p_curr;
                p_curr = p_next;
                q_prev = q_curr;
                q_curr = q_next;
            }
            return convergents;
        }
    }
}
