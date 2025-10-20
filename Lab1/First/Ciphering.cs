using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using CipheringKeys;

namespace MyCiphering
{
    #region interfaces
    public interface ICipheringMode
    {
        public void cipherBlock(byte[] bytes, ref byte[] resBytes);
        public void cipherBlock(String sourcePath, String destPath);
    }

    public interface IPackingMode
    {
        public byte[] packMissingBytes(byte[] bytes, int neededLength);
    }

    public interface IGetRoundKeys
    {
        public byte[][] getRoundKeys(in byte[] key);
    }

    public interface IRoundTransmition
    {
        public byte[] roundTransmition(in byte[] bytes, in byte[] roundKey);
        public byte[] roundTransmitionRev(in byte[] bytes, in byte[] roundKey);
    }

    public interface IBlockCiphering
    {
        public byte[] cipherBlock(in byte[] bytes);
        public byte[] decipherBlock(in byte[] bytes);
    }

    #endregion

    public enum CipheringMode : byte
    {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
        CTR,
        RandomDelta,
    }

    public class Permutations
    {
        public enum Endian
        {
            LittleEndian = 0,
            BigEndian = 1,
        }

        public enum StartIndex
        {
            Zero = 0,
            First = 1,
        }

        public static void bitPermutations(
            ref byte[] bytes,
            in byte[] pBlock,
            StartIndex startIndex,
            Endian endian
        )
        {
            if (pBlock == null || pBlock.Length == 0)
                return;

            int outputBitCount = pBlock.Length;
            int outputByteCount = (outputBitCount + 7) / 8;
            int inputBitCount = bytes.Length * 8;

            byte[] result = new byte[outputByteCount];

            for (int outBit = 0; outBit < outputBitCount; outBit++)
            {
                int inBitPos = pBlock[outBit];
                if (startIndex == StartIndex.First)
                    inBitPos--;

                if (inBitPos < 0 || inBitPos >= inputBitCount)
                    continue;

                int inByte = inBitPos / 8;
                int inBit = inBitPos % 8;

                int inBitIndex = (endian == Endian.BigEndian) ? (7 - inBit) : inBit;
                byte bitValue = (byte)((bytes[inByte] >> inBitIndex) & 1);

                if (bitValue == 1)
                {
                    int outByte = outBit / 8;
                    int outBitInByte = outBit % 8;

                    int outBitIndex =
                        (endian == Endian.BigEndian) ? (7 - outBitInByte) : outBitInByte;
                    result[outByte] |= (byte)(1 << outBitIndex);
                }
            }

            bytes = result;
        }
    }

    #region Packing
    public class ZeroesPackingMode : IPackingMode
    {
        public byte[] packMissingBytes(byte[] bytes, int neededLength)
        {
            if (bytes.Length != neededLength)
            {
                byte[] result = new byte[neededLength];
                Array.Copy(bytes, result, bytes.Length);
                Array.Fill<byte>(result, 0, bytes.Length, neededLength - bytes.Length);
                return result;
            }
            return bytes;
        }
    }

    public class ANSI_X923PackingMode : IPackingMode
    {
        public byte[] packMissingBytes(byte[] bytes, int neededLength)
        {
            if (bytes.Length != neededLength)
            {
                byte[] result = new byte[neededLength];
                Array.Copy(bytes, result, bytes.Length);

                Array.Fill<byte>(result, 0, bytes.Length, neededLength - bytes.Length - 1);
                result[result.Length - 1] = (byte)(neededLength - bytes.Length);
                return result;
            }
            return bytes;
        }
    }

    public class PKCS7PackingMode : IPackingMode
    {
        public byte[] packMissingBytes(byte[] bytes, int neededLength)
        {
            if (bytes.Length != neededLength)
            {
                byte[] result = new byte[neededLength];
                Array.Copy(bytes, result, bytes.Length);

                Array.Fill<byte>(
                    result,
                    (byte)(neededLength - bytes.Length),
                    bytes.Length,
                    neededLength - bytes.Length
                );
                return result;
            }
            return bytes;
        }
    }

    public class ISO10126PackingMode : IPackingMode
    {
        public byte[] packMissingBytes(byte[] bytes, int neededLength)
        {
            if (bytes.Length != neededLength)
            {
                byte[] result = new byte[neededLength];
                Array.Copy(bytes, result, bytes.Length);

                Random rand = new Random();
                for (int i = bytes.Length; i < neededLength - 1; i++)
                {
                    result[i] = (byte)rand.Next(0, 256);
                }
                result[result.Length - 1] = (byte)(neededLength - bytes.Length);
                return result;
            }
            return bytes;
        }
    }

    public enum PackingMode : byte
    {
        Zeros,
        ANSI_X923,
        PKCS7,
        ISO10126,
    }

    #endregion


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
        /* private */public byte[] feistelFunction(in byte[] right, in byte[] roundKey)
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

    public class FeistelNetwork : IRoundTransmition
    {
        private IGetRoundKeys getRoundKeys;
        private IRoundTransmition roundTransmittionReal;

        public FeistelNetwork(IGetRoundKeys getRoundKeys, IRoundTransmition roundTransmittion)
        {
            this.getRoundKeys = getRoundKeys;
            this.roundTransmittionReal = roundTransmittion;
        }

        public byte[] feistelNetwork(in byte[] bytes, in byte[] key)
        {
            byte[] result = (byte[])bytes.Clone();
            Permutations.bitPermutations(
                ref result,
                KeyArray.getIP(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );
            byte[][] roundKeys = getRoundKeys.getRoundKeys(key);

            for (int i = 0; i < 16; i++)
            {
                result = roundTransmition(in result, roundKeys[i]);
            }
            Permutations.bitPermutations(
                ref result,
                KeyArray.getIPRev(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );
            return result;
        }

        public byte[] feistelNetworkRev(in byte[] bytes, in byte[] key)
        {
            byte[] result = (byte[])bytes.Clone();

            Permutations.bitPermutations(
                ref result,
                KeyArray.getIP(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );

            byte[][] roundKeys = getRoundKeys.getRoundKeys(key);

            for (int i = 15; i >= 0; i--)
            {
                result = roundTransmitionRev(in result, roundKeys[i]);
            }

            Permutations.bitPermutations(
                ref result,
                KeyArray.getIPRev(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );

            return result;
        }

        public byte[] roundTransmition(in byte[] bytes, in byte[] roundKey)
        {
            return roundTransmittionReal.roundTransmition(bytes, in roundKey);
        }

        public byte[] roundTransmitionRev(in byte[] bytes, in byte[] roundKey)
        {
            return roundTransmittionReal.roundTransmitionRev(bytes, in roundKey);
        }
    }
}
