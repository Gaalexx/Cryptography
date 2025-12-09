using System;
using System.Collections.Generic;

namespace MathLab3
{
    class GaluaField
    {
        public const ushort ModPoly = 0x11B;
        public const int FieldSize = 256;

        public static byte Sum(byte a, byte b)
        {
            return (byte)(a ^ b);
        }

        private static void EnsureIrreducibleModulus(ushort modPoly)
        {
            if (!IrreducibilityCheck(modPoly))
            {
                throw new ArgumentException("Модуль приводим над GF(2).");
            }
        }

        public static byte Multiplication(byte a, byte b, ushort modPoly = ModPoly)
        {
            EnsureIrreducibleModulus(modPoly);

            byte result = 0;
            ushort aa = a;

            while (b > 0)
            {
                if ((b & 1) != 0)
                {
                    result ^= (byte)aa;
                }

                aa <<= 1;

                if ((aa & 0x100) != 0)
                {
                    aa ^= modPoly;
                }

                b >>= 1;
            }

            return result;
        }

        public static byte BinPow(byte number, int power, ushort modPoly = ModPoly)
        {
            byte result = 1;
            byte baseVal = number;

            while (power > 0)
            {
                if ((power & 1) != 0)
                {
                    result = Multiplication(result, baseVal, modPoly);
                }

                baseVal = Multiplication(baseVal, baseVal, modPoly);
                power >>= 1;
            }

            return result;
        }

        public static byte GetReverse(byte number, ushort modPoly = ModPoly)
        {
            EnsureIrreducibleModulus(modPoly);

            if (number == 0)
            {
                throw new ArgumentException("0 не имеет обратного элемента в поле.");
            }

            return BinPow(number, FieldSize - 2, modPoly);
        }

        public static int Degree(ushort polynomial)
        {
            if (polynomial == 0)
            {
                return -1;
            }

            int deg = -1;
            while (polynomial != 0)
            {
                polynomial >>= 1;
                deg++;
            }
            return deg;
        }

        private static ulong PolynomialMulRaw(ushort a, ushort b)
        {
            ulong res = 0;
            ulong aa = a;
            ushort bb = b;

            while (bb != 0)
            {
                if ((bb & 1) != 0)
                {
                    res ^= aa;
                }
                aa <<= 1;
                bb >>= 1;
            }

            return res;
        }

        private static ushort PolynomialMod(ulong a, ushort b)
        {
            if (b == 0)
            {
                return (ushort)a;
            }

            int degB = Degree(b);

            while (true)
            {
                if (a == 0)
                {
                    break;
                }

                int degA = -1;
                ulong temp = a;
                while (temp != 0)
                {
                    temp >>= 1;
                    degA++;
                }

                if (degA < degB)
                {
                    break;
                }

                a ^= (ulong)b << (degA - degB);
            }

            return (ushort)a;
        }

        private static ushort PolynomialGcd(ushort a, ushort b)
        {
            while (b != 0)
            {
                ushort temp = b;
                b = PolynomialMod(a, b);
                a = temp;
            }
            return a;
        }

        private static ushort PolynomialPowMod(ushort x, int power, ushort mod)
        {
            ushort result = 1;
            ushort current = x;

            while (power > 0)
            {
                if ((power & 1) != 0)
                {
                    result = PolynomialMod(PolynomialMulRaw(result, current), mod);
                }

                current = PolynomialMod(PolynomialMulRaw(current, current), mod);
                power >>= 1;
            }

            return result;
        }

        private static IEnumerable<int> PrimeDivisors(int n)
        {
            int x = n;
            for (int p = 2; p * p <= x; p++)
            {
                if (x % p == 0)
                {
                    yield return p;
                    while (x % p == 0)
                    {
                        x /= p;
                    }
                }
            }
            if (x > 1)
            {
                yield return x;
            }
        }

        public static bool IsIrreducible(ushort polynomial)
        {
            if (polynomial == 0)
                return false;

            int m = Degree(polynomial);
            if (m <= 0)
            {
                return false;
            }

            const ushort xPoly = 0b10;

            int exp1 = 1 << m;
            ushort x2m = PolynomialPowMod(xPoly, exp1, polynomial);
            if (x2m != xPoly)
            {
                return false;
            }

            foreach (int r in PrimeDivisors(m))
            {
                int exp = 1 << (m / r);
                ushort xr = PolynomialPowMod(xPoly, exp, polynomial);
                ushort xrMinusX = (ushort)(xr ^ xPoly);
                if (PolynomialGcd(polynomial, xrMinusX) != 1)
                {
                    return false;
                }
            }

            return true;
        }

        public static bool IrreducibilityCheck(ushort polynomial)
        {
            return IsIrreducible(polynomial) && Degree(polynomial) == 8;
        }

        private static ushort PolynomialDiv(ushort a, ushort b)
        {
            if (b == 0)
                throw new DivideByZeroException();

            ulong dividend = a;
            ushort quotient = 0;
            int degB = Degree(b);

            while (true)
            {
                if (dividend == 0)
                {
                    break;
                }

                int degA = -1;
                ulong temp = dividend;
                while (temp != 0)
                {
                    temp >>= 1;
                    degA++;
                }

                if (degA < degB)
                {
                    break;
                }

                int shift = degA - degB;
                quotient |= (ushort)(1 << shift);
                dividend ^= (ulong)b << shift;
            }

            return quotient;
        }

        private static void FactorRecursive(ushort p, List<ushort> factors)
        {
            if (p == 0 || p == 1)
            {
                return;
            }

            if (IsIrreducible(p))
            {
                factors.Add(p);
                return;
            }

            int maxDeg = Degree(p);

            for (int deg = 1; deg <= maxDeg / 2; deg++)
            {
                int start = 1 << deg;
                int end = 1 << (deg + 1);

                for (int q = start; q < end; q++)
                {
                    ushort uq = (ushort)q;
                    if (!IsIrreducible(uq))
                    {
                        continue;
                    }

                    if (PolynomialMod(p, uq) == 0)
                    {
                        ushort quotient = p;
                        while (PolynomialMod(quotient, uq) == 0)
                        {
                            quotient = PolynomialDiv(quotient, uq);
                            factors.Add(uq);
                        }
                        FactorRecursive(quotient, factors);
                        return;
                    }
                }
            }

            factors.Add(p);
        }

        public static bool IrreducibleDegree8(ushort polynomial)
        {
            return Degree(polynomial) == 8 && IsIrreducible(polynomial);
        }

        public static ushort[] GetIrreduciblePolynomials()
        {
            var list = new List<ushort>();

            for (ushort p = 0; p < 512; p++)
            {
                if (IrreducibleDegree8(p))
                {
                    list.Add(p);
                }
            }

            return list.ToArray();
        }

        public static IEnumerable<ushort> DecomposePolynomial(ulong polynomial)
        {
            if (polynomial == 0UL)
            {
                yield return 0;
                yield break;
            }

            if (polynomial > ushort.MaxValue)
            {
                throw new NotSupportedException(
                    "Факторизация реализована только для полиномов степени ≤ 15."
                );
            }

            ushort p = (ushort)polynomial;

            if (p == 1)
            {
                yield return 1;
                yield break;
            }

            var factors = new List<ushort>();
            FactorRecursive(p, factors);

            foreach (var f in factors)
            {
                yield return f;
            }
        }

        public static void ShiftRows(byte[] state, int Nb)
        {
            byte[] tmp = new byte[state.Length];

            for (int r = 0; r < 4; r++)
            {
                int shift;
                switch (r)
                {
                    case 0:
                        shift = 0;
                        break;
                    case 1:
                        shift = 1;
                        break;
                    case 2:
                        shift = (Nb == 8) ? 3 : 2;
                        break;
                    case 3:
                        shift = (Nb == 8) ? 4 : 3;
                        break;
                    default:
                        shift = 0;
                        break;
                }

                for (int c = 0; c < Nb; c++)
                {
                    tmp[r + 4 * c] = state[r + 4 * ((c + shift) % Nb)];
                }
            }

            Buffer.BlockCopy(tmp, 0, state, 0, state.Length);
        }

        public static void InvShiftRows(byte[] state, int Nb)
        {
            byte[] tmp = new byte[state.Length];

            for (int r = 0; r < 4; r++)
            {
                int shift;
                switch (r)
                {
                    case 0:
                        shift = 0;
                        break;
                    case 1:
                        shift = 1;
                        break;
                    case 2:
                        shift = (Nb == 8) ? 3 : 2;
                        break;
                    case 3:
                        shift = (Nb == 8) ? 4 : 3;
                        break;
                    default:
                        shift = 0;
                        break;
                }

                for (int c = 0; c < Nb; c++)
                {
                    int srcCol = (c - shift) % Nb;
                    if (srcCol < 0)
                        srcCol += Nb;

                    tmp[r + 4 * c] = state[r + 4 * srcCol];
                }
            }

            Buffer.BlockCopy(tmp, 0, state, 0, state.Length);
        }

        public static void MixColumns(byte[] state, int Nb)
        {
            byte[] tmp = new byte[state.Length];

            for (int c = 0; c < Nb; c++)
            {
                int i = 4 * c;

                byte a0 = state[i + 0];
                byte a1 = state[i + 1];
                byte a2 = state[i + 2];
                byte a3 = state[i + 3];

                tmp[i + 0] = (byte)(
                    GaluaField.Multiplication(0x02, a0)
                    ^ GaluaField.Multiplication(0x03, a1)
                    ^ a2
                    ^ a3
                );

                tmp[i + 1] = (byte)(
                    a0
                    ^ GaluaField.Multiplication(0x02, a1)
                    ^ GaluaField.Multiplication(0x03, a2)
                    ^ a3
                );

                tmp[i + 2] = (byte)(
                    a0
                    ^ a1
                    ^ GaluaField.Multiplication(0x02, a2)
                    ^ GaluaField.Multiplication(0x03, a3)
                );

                tmp[i + 3] = (byte)(
                    GaluaField.Multiplication(0x03, a0)
                    ^ a1
                    ^ a2
                    ^ GaluaField.Multiplication(0x02, a3)
                );
            }

            Buffer.BlockCopy(tmp, 0, state, 0, state.Length);
        }

        public static void InvMixColumns(byte[] state, int Nb)
        {
            byte[] tmp = new byte[state.Length];

            for (int c = 0; c < Nb; c++)
            {
                int i = 4 * c;

                byte a0 = state[i + 0];
                byte a1 = state[i + 1];
                byte a2 = state[i + 2];
                byte a3 = state[i + 3];

                tmp[i + 0] = (byte)(
                    GaluaField.Multiplication(0x0e, a0)
                    ^ GaluaField.Multiplication(0x0b, a1)
                    ^ GaluaField.Multiplication(0x0d, a2)
                    ^ GaluaField.Multiplication(0x09, a3)
                );

                tmp[i + 1] = (byte)(
                    GaluaField.Multiplication(0x09, a0)
                    ^ GaluaField.Multiplication(0x0e, a1)
                    ^ GaluaField.Multiplication(0x0b, a2)
                    ^ GaluaField.Multiplication(0x0d, a3)
                );

                tmp[i + 2] = (byte)(
                    GaluaField.Multiplication(0x0d, a0)
                    ^ GaluaField.Multiplication(0x09, a1)
                    ^ GaluaField.Multiplication(0x0e, a2)
                    ^ GaluaField.Multiplication(0x0b, a3)
                );

                tmp[i + 3] = (byte)(
                    GaluaField.Multiplication(0x0b, a0)
                    ^ GaluaField.Multiplication(0x0d, a1)
                    ^ GaluaField.Multiplication(0x09, a2)
                    ^ GaluaField.Multiplication(0x0e, a3)
                );
            }

            Buffer.BlockCopy(tmp, 0, state, 0, state.Length);
        }
    }
}
