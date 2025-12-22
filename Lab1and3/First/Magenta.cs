using System;

namespace MyCiphering
{
    class MagentaGetRoundKeys : IGetRoundKeys
    {
        public byte[][] getRoundKeys(in byte[] key)
        {
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                throw new Exception("Ключ должен быть размером 128, 192 или 256 бит!");
            }

            byte[][] subKeys = new byte[key.Length / 8][];
            for (int i = 0; i < subKeys.Length; i++)
            {
                subKeys[i] = new byte[8];
                Array.Copy(key, i * 8, subKeys[i], 0, 8);
            }

            byte[][] roundKeys;
            switch (key.Length)
            {
                case 16:
                    roundKeys = new byte[6][];
                    roundKeys[0] = subKeys[0];
                    roundKeys[1] = subKeys[0];
                    roundKeys[2] = subKeys[1];
                    roundKeys[3] = subKeys[1];
                    roundKeys[4] = subKeys[0];
                    roundKeys[5] = subKeys[0];
                    break;
                case 24:
                    roundKeys = new byte[6][];
                    roundKeys[0] = subKeys[0];
                    roundKeys[1] = subKeys[1];
                    roundKeys[2] = subKeys[2];
                    roundKeys[3] = subKeys[2];
                    roundKeys[4] = subKeys[1];
                    roundKeys[5] = subKeys[0];
                    break;
                case 32:
                    roundKeys = new byte[8][];
                    roundKeys[0] = subKeys[0];
                    roundKeys[1] = subKeys[1];
                    roundKeys[2] = subKeys[2];
                    roundKeys[3] = subKeys[3];
                    roundKeys[4] = subKeys[3];
                    roundKeys[5] = subKeys[2];
                    roundKeys[6] = subKeys[1];
                    roundKeys[7] = subKeys[0];
                    break;
                default:
                    throw new Exception("Ключ должен быть размером 128, 192 или 256 бит!");
            }

            return roundKeys;
        }
    }

    class MagentaRoundTransmition : IRoundTransmition
    {
        private readonly byte[] sBox;

        public byte RoundsAmount { get; private set; }

        public MagentaRoundTransmition(byte[] key, byte[] sBox)
        {
            this.sBox = (byte[])sBox.Clone();
            switch (key.Length)
            {
                case 16:
                    RoundsAmount = 6;
                    break;
                case 24:
                    RoundsAmount = 6;
                    break;
                case 32:
                    RoundsAmount = 8;
                    break;
                default:
                    throw new Exception("Ключ должен быть размером 128, 192 или 256 бит!");
            }
        }

        private byte f(byte x)
        {
            return sBox[x];
        }

        private byte a(byte x, byte y)
        {
            return f((byte)(x ^ f(y)));
        }

        private (byte, byte) pe(byte x, byte y)
        {
            return (a(x, y), a(y, x));
        }

        private byte[] butterfly(in byte[] bytes)
        {
            if (bytes.Length != 16)
                throw new Exception("Блок должен быть размером 128 бит!");

            byte[] result = new byte[16];

            for (int i = 0; i < 8; i++)
            {
                var pair = pe(bytes[i], bytes[i + 8]);
                result[2 * i] = pair.Item1;
                result[2 * i + 1] = pair.Item2;
            }

            return result;
        }

        private byte[] t(in byte[] bytes)
        {
            return butterfly(butterfly(butterfly(butterfly(bytes))));
        }

        private byte[] xorBytes(in byte[] bytes1, in byte[] bytes2)
        {
            if (bytes1.Length != bytes2.Length)
            {
                throw new Exception("Блоки должны быть одинакового размера!");
            }

            byte[] result = new byte[bytes1.Length];

            for (int i = 0; i < bytes1.Length; i++)
            {
                result[i] = (byte)(bytes1[i] ^ bytes2[i]);
            }

            return result;
        }

        private byte[] permuteEvenOdd(in byte[] bytes)
        {
            if (bytes.Length != 16)
                throw new Exception("Блок должен быть размером 128 бит!");

            var (even, odd) = splitEvenOdd(bytes);
            byte[] result = new byte[16];

            Array.Copy(even, 0, result, 0, 8);
            Array.Copy(odd, 0, result, 8, 8);

            return result;
        }

        private byte[] c(int j, in byte[] x)
        {
            if (j == 1)
            {
                return t(x);
            }
            else
            {
                var cPrev = c(j - 1, x);

                var s = permuteEvenOdd(cPrev);

                var z = xorBytes(x, s);

                return t(z);
            }
        }

        private byte[] e3(byte[] X)
        {
            byte[] C3 = c(3, X);
            var (even, odd) = splitEvenOdd(C3);
            return even;
        }

        private (byte[], byte[]) splitEvenOdd(in byte[] bytes)
        {
            if (bytes.Length != 16)
            {
                throw new Exception("Блок должен быть размером 128 бит!");
            }

            byte[] even = new byte[8];
            byte[] odd = new byte[8];

            for (int i = 0; i < bytes.Length; i += 2)
            {
                even[i / 2] = bytes[i];
                odd[i / 2] = bytes[i + 1];
            }

            return (even, odd);
        }

        private (byte[], byte[]) split(in byte[] bytes)
        {
            if (bytes.Length != 16)
            {
                throw new Exception("Блок должен быть размером 128 бит!");
            }

            byte[] left = new byte[8];
            byte[] right = new byte[8];

            Array.Copy(bytes, 0, left, 0, 8);
            Array.Copy(bytes, 8, right, 0, 8);

            return (left, right);
        }

        public byte[] roundTransmition(in byte[] bytes, in byte[] roundKey)
        {
            var (left, right) = split(bytes);
            byte[] z = new byte[16];
            Array.Copy(right, 0, z, 0, 8);
            Array.Copy(roundKey, 0, z, 8, 8);

            byte[] U = e3(z);

            byte[] L2 = right;

            byte[] R2 = xorBytes(left, U);

            byte[] result = new byte[16];
            Array.Copy(L2, 0, result, 0, 8);
            Array.Copy(R2, 0, result, 8, 8);

            return result;
        }

        public byte[] roundTransmitionRev(in byte[] bytes, in byte[] roundKey)
        {
            var (leftPrime, rightPrime) = split(bytes);

            byte[] R = leftPrime;

            byte[] z = new byte[16];
            Array.Copy(R, 0, z, 0, 8);
            Array.Copy(roundKey, 0, z, 8, 8);

            byte[] U = e3(z);

            byte[] L = xorBytes(rightPrime, U);

            byte[] result = new byte[16];
            Array.Copy(L, 0, result, 0, 8);
            Array.Copy(R, 0, result, 8, 8);

            return result;
        }
    }

    class Magenta : FeistelNetwork, ICipheringAlgorithm
    {
        public Magenta(byte[] key, ushort modPoly = MagentaArray.DefaultModPoly)
            : base(
                new MagentaGetRoundKeys(),
                new MagentaRoundTransmition(key, MagentaArray.GetSBox(modPoly)),
                key
            ) { }

        public byte BlockSize { get; protected set; } = 16;

        public byte[] cipherBlock(in byte[] blockToCipher)
        {
            byte[] result = (byte[])blockToCipher.Clone();
            return feistelNetwork(ref result);
        }

        public byte[] decipherBlock(in byte[] blockToDecipher)
        {
            byte[] result = (byte[])blockToDecipher.Clone();
            return feistelNetworkRev(ref result);
        }
    }
}
