using System;

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

        public static readonly byte[] SBox = BuildSBox();
        public static readonly byte[] InvSBox = BuildInvSBox();

        public static byte SubByte(byte x)
        {
            byte inv = x == 0 ? (byte)0 : GaluaField.GetReverse(x);

            return AffineTransform(inv);
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

        private static byte[] BuildSBox()
        {
            var sbox = new byte[256];

            for (int x = 0; x < 256; x++)
            {
                sbox[x] = SubByte((byte)x);
            }

            return sbox;
        }

        private static byte[] BuildInvSBox()
        {
            var inv = new byte[256];

            for (int i = 0; i < 256; i++)
            {
                byte s = SBox[i];
                inv[s] = (byte)i;
            }

            return inv;
        }
    }
}
