using System;
using System.Collections.Generic;

namespace MathLab3
{
    class RijndaelSBox
    {
        private const byte AffineConst = 0x63;

        public static readonly byte[] ABox =
        {
            1,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            1,
        };

        private static readonly Dictionary<ushort, byte[]> SBoxCache = new();
        private static readonly Dictionary<ushort, byte[]> InvSBoxCache = new();
        private static readonly object CacheLock = new();

        public static byte[] GetSBox(ushort modPoly = GaluaField.ModPoly)
        {
            ValidateModPoly(modPoly);

            lock (CacheLock)
            {
                if (!SBoxCache.TryGetValue(modPoly, out var sbox))
                {
                    sbox = BuildSBox(modPoly);
                    var inv = BuildInvSBox(sbox);
                    SBoxCache[modPoly] = sbox;
                    InvSBoxCache[modPoly] = inv;
                }

                return sbox;
            }
        }

        public static byte[] GetInvSBox(ushort modPoly = GaluaField.ModPoly)
        {
            ValidateModPoly(modPoly);

            lock (CacheLock)
            {
                if (!InvSBoxCache.TryGetValue(modPoly, out var inv))
                {
                    var sbox = GetSBox(modPoly);
                    if (!InvSBoxCache.TryGetValue(modPoly, out inv))
                    {
                        inv = BuildInvSBox(sbox);
                        InvSBoxCache[modPoly] = inv;
                    }
                }

                return inv;
            }
        }

        public static byte SubByte(byte x, ushort modPoly = GaluaField.ModPoly)
        {
            return GetSBox(modPoly)[x];
        }

        private static byte AffineTransform(byte y)
        {
            byte result = 0;

            for (int row = 0; row < 8; row++)
            {
                int bit = (AffineConst >> row) & 1;

                for (int col = 0; col < 8; col++)
                {
                    if (ABox[row * 8 + col] != 0)
                    {
                        bit ^= (y >> col) & 1;
                    }
                }

                result |= (byte)(bit << row);
            }

            return result;
        }

        private static byte[] BuildSBox(ushort modPoly)
        {
            var sbox = new byte[256];

            for (int x = 0; x < 256; x++)
            {
                byte inv = x == 0 ? (byte)0 : GaluaField.GetReverse((byte)x, modPoly);
                sbox[x] = AffineTransform(inv);
            }

            return sbox;
        }

        private static byte[] BuildInvSBox(byte[] sbox)
        {
            var inv = new byte[256];

            for (int i = 0; i < 256; i++)
            {
                byte s = sbox[i];
                inv[s] = (byte)i;
            }

            return inv;
        }

        private static void ValidateModPoly(ushort modPoly)
        {
            if (!GaluaField.IrreducibilityCheck(modPoly))
            {
                throw new ArgumentException("Модуль приводим над GF(2).");
            }
        }
    }
}
