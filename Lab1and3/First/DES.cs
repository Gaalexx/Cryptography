using CipheringKeys;
using MyCiphering;

namespace MyCiphering
{
    public class RoundKeys : IGetRoundKeys
    {
        private static readonly int[] ShiftBits =
        {
            1,
            1,
            2,
            2,
            2,
            2,
            2,
            2,
            1,
            2,
            2,
            2,
            2,
            2,
            2,
            1,
        };

        public byte[][] getRoundKeys(in byte[] key)
        {
            byte[] key56 = (byte[])key.Clone();
            Permutations.bitPermutations(
                ref key56,
                CipheringKeys.KeyArray.getPC1(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );
            if (key56.Length != 7)
            {
                byte[] tmp = new byte[7];
                Array.Copy(key56, tmp, Math.Min(key56.Length, 7));
                key56 = tmp;
            }
            ulong combined56 = 0;
            for (int i = 0; i < 7; i++)
            {
                combined56 = (combined56 << 8) | key56[i];
            }

            const uint mask28 = 0x0FFFFFFF;
            uint C = (uint)((combined56 >> 28) & mask28);
            uint D = (uint)(combined56 & mask28);

            byte[][] roundKeys = new byte[16][];

            for (int round = 0; round < 16; round++)
            {
                int shift = ShiftBits[round];
                C = LeftRotate28(C, shift);
                D = LeftRotate28(D, shift);

                ulong cd = ((ulong)C << 28) | (ulong)D;

                byte[] cdBytes = new byte[7];
                for (int i = 6; i >= 0; i--)
                {
                    cdBytes[i] = (byte)(cd & 0xFF);
                    cd >>= 8;
                }

                byte[] k56 = (byte[])cdBytes.Clone();
                Permutations.bitPermutations(
                    ref k56,
                    KeyArray.getPC2(),
                    Permutations.StartIndex.First,
                    Permutations.Endian.BigEndian
                );
                roundKeys[round] = k56;
            }

            return roundKeys;
        }

        private static uint LeftRotate28(uint value, int shift)
        {
            const uint mask28 = 0x0FFFFFFF;
            shift %= 28;
            return ((value << shift) | (value >> (28 - shift))) & mask28;
        }
    }

    public class RoundTransmition : IRoundTransmition
    {
        public byte RoundsAmount { get; } = 16;

        private byte[] feistelFunction(in byte[] right, in byte[] roundKey)
        {
            byte[] expanded = (byte[])right.Clone();
            Permutations.bitPermutations(
                ref expanded,
                KeyArray.getEBlock(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );

            for (int i = 0; i < expanded.Length; i++)
            {
                expanded[i] = (byte)(expanded[i] ^ roundKey[i]);
            }

            byte[,,] sBoxes = KeyArray.getSBoxes();
            byte[] sBoxResult = new byte[4];
            Array.Fill<byte>(sBoxResult, 0);

            for (int i = 0; i < 8; i++)
            {
                int startBit = i * 6;
                byte sixBits = 0;
                for (int j = 0; j < 6; j++)
                {
                    int bitIndex = startBit + j;
                    int byteIndex = bitIndex / 8;
                    int bitInByte = 7 - (bitIndex % 8);

                    byte bitValue = 0;
                    if (byteIndex < expanded.Length)
                    {
                        bitValue = (byte)((expanded[byteIndex] >> bitInByte) & 0x01);
                    }
                    sixBits = (byte)((sixBits << 1) | bitValue);
                }

                byte row = (byte)((((sixBits >> 5) & 0x01) << 1) | (sixBits & 0x01));
                byte col = (byte)((sixBits >> 1) & 0x0F);
                byte sBoxValue = sBoxes[i, row, col];

                int resultStartBit = i * 4;
                for (int b = 0; b < 4; b++)
                {
                    int targetBitIndex = resultStartBit + b;
                    int targetByte = targetBitIndex / 8;
                    int targetBitInByte = 7 - (targetBitIndex % 8);
                    byte bitValue = (byte)((sBoxValue >> (3 - b)) & 0x01);
                    sBoxResult[targetByte] |= (byte)(bitValue << targetBitInByte);
                }
            }

            Permutations.bitPermutations(
                ref sBoxResult,
                CipheringKeys.KeyArray.getPBlock(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );
            return sBoxResult;
        }

        public byte[] roundTransmition(in byte[] bytes, in byte[] roundKey)
        {
            byte[] left = new byte[4];
            byte[] right = new byte[4];

            Array.Copy(bytes, 0, left, 0, 4);
            Array.Copy(bytes, 4, right, 0, 4);

            byte[] feistelResult = feistelFunction(right, roundKey);

            byte[] newRight = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                newRight[i] = (byte)(left[i] ^ feistelResult[i]);
            }

            return right.Concat(newRight).ToArray();
        }

        public byte[] roundTransmitionRev(in byte[] bytes, in byte[] roundKey)
        {
            byte[] left = new byte[4];
            byte[] right = new byte[4];

            Array.Copy(bytes, 0, left, 0, 4);
            Array.Copy(bytes, 4, right, 0, 4);

            byte[] feistelResult = feistelFunction(left, roundKey);

            byte[] originalRight = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                originalRight[i] = (byte)(right[i] ^ feistelResult[i]);
            }

            return originalRight.Concat(left).ToArray();
        }
    }

    public class FeistelNetwork
    {
        protected IGetRoundKeys getRoundKeys;
        protected IRoundTransmition roundTransmittion;
        private byte[][] roundKeys;

        public FeistelNetwork(
            IGetRoundKeys getRoundKeys,
            IRoundTransmition roundTransmittion,
            byte[] key
        )
        {
            this.getRoundKeys = getRoundKeys;
            this.roundTransmittion = roundTransmittion;
            roundKeys = getRoundKeys.getRoundKeys(in key);
        }

        public byte[] feistelNetwork(in byte[] bytes)
        {
            byte[] result = (byte[])bytes.Clone();
            if (bytes.Length == 8)
            {
                Permutations.bitPermutations(
                    ref result,
                    KeyArray.getIP(),
                    Permutations.StartIndex.First,
                    Permutations.Endian.BigEndian
                );
            }

            for (int i = 0; i < roundTransmittion.RoundsAmount; i++)
            {
                result = roundTransmittion.roundTransmition(in result, roundKeys[i]);
            }

            if (bytes.Length == 8)
            {
                Permutations.bitPermutations(
                    ref result,
                    KeyArray.getIPRev(),
                    Permutations.StartIndex.First,
                    Permutations.Endian.BigEndian
                );
            }
            return result;
        }

        public byte[] feistelNetworkRev(in byte[] bytes)
        {
            byte[] result = (byte[])bytes.Clone();
            if (bytes.Length == 8)
            {
                Permutations.bitPermutations(
                    ref result,
                    KeyArray.getIP(),
                    Permutations.StartIndex.First,
                    Permutations.Endian.BigEndian
                );
            }

            for (int i = roundTransmittion.RoundsAmount - 1; i >= 0; i--)
            {
                result = roundTransmittion.roundTransmitionRev(in result, roundKeys[i]);
            }
            if (bytes.Length == 8)
            {
                Permutations.bitPermutations(
                    ref result,
                    KeyArray.getIPRev(),
                    Permutations.StartIndex.First,
                    Permutations.Endian.BigEndian
                );
            }
            return result;
        }
    }

    public class DES : FeistelNetwork, ICipheringAlgorithm
    {
        public virtual byte BlockSize { get; protected set; } = 8;

        public DES(byte[] key)
            : base(new RoundKeys(), new RoundTransmition(), key) { }

        public DES(byte[] key, IGetRoundKeys getRoundKeys, IRoundTransmition roundTransmition)
            : base(getRoundKeys, roundTransmition, key) { }

        public virtual byte[] cipherBlock(in byte[] blockToCipher)
        {
            return feistelNetwork(blockToCipher);
        }

        public virtual byte[] decipherBlock(in byte[] blockToDecipher)
        {
            return feistelNetworkRev(blockToDecipher);
        }
    }
}
