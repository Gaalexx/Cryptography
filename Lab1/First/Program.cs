using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using CipheringKeys;
using MyCiphering;
using NUnit.Framework.Internal;

namespace Program
{
    class Program
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
            if (pBlock.Length < 8 || bytes.Length < 1 || pBlock.Length % 8 != 0)
            {
                return;
            }

            int blockSizeBytes = pBlock.Length / 8;

            if (bytes.Length % blockSizeBytes != 0)
            {
                int newLength =
                    (bytes.Length + blockSizeBytes - 1) / blockSizeBytes * blockSizeBytes;
                byte[] bufferBytes = new byte[newLength];
                Array.Copy(bytes, bufferBytes, bytes.Length);
                bytes = bufferBytes;
            }

            byte[] localpBlock = (byte[])pBlock.Clone();
            byte[] resBytes = new byte[bytes.Length];
            Array.Fill<byte>(resBytes, 0);

            if (startIndex == StartIndex.First)
            {
                for (int i = 0; i < localpBlock.Length; i++)
                {
                    localpBlock[i] -= 1;
                }
            }

            for (int blockStart = 0; blockStart < bytes.Length; blockStart += blockSizeBytes)
            {
                for (int bitPos = 0; bitPos < pBlock.Length; bitPos++)
                {
                    int sourceByteIndex = blockStart + (bitPos / 8);
                    if (sourceByteIndex >= bytes.Length)
                        continue;

                    int bitIndexInByte =
                        (endian == Endian.LittleEndian) ? (bitPos % 8) : (7 - (bitPos % 8));

                    byte bitValue = (byte)((bytes[sourceByteIndex] >> bitIndexInByte) & 1);

                    if (bitValue == 1)
                    {
                        int newBitPos = localpBlock[bitPos];

                        if (newBitPos < 0 || newBitPos >= pBlock.Length)
                            continue;

                        int targetByteIndex = blockStart + (newBitPos / 8);
                        if (targetByteIndex >= resBytes.Length)
                            continue;

                        int newBitIndexInByte =
                            (endian == Endian.LittleEndian)
                                ? (newBitPos % 8)
                                : (7 - (newBitPos % 8));

                        resBytes[targetByteIndex] |= (byte)(1 << newBitIndexInByte);
                    }
                }
            }

            bytes = resBytes;
        }

        public static void TestFeistelConsistency()
        {
            var roundKeys = new RoundKeys();
            var roundTrans = new RoundTransmition();
            var feistel = new FeistelNetwork(roundKeys, roundTrans);

            byte[] testData = new byte[8] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
            byte[] testKey = new byte[8] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBD, 0xDF, 0xF1 };

            byte[] encrypted = feistel.feistelNetwork(testData, testKey);
            byte[] decrypted = feistel.feistelNetworkRev(encrypted, testKey);

            Console.WriteLine("Original: " + BitConverter.ToString(testData));
            Console.WriteLine("Encrypted: " + BitConverter.ToString(encrypted));
            Console.WriteLine("Decrypted: " + BitConverter.ToString(decrypted));
            Console.WriteLine("Success: " + testData.SequenceEqual(decrypted));
        }

        public static void TestFeistelConsistency1()
        {
            byte[] plainText = new byte[] { 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };
            byte[] key = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            var rk = new RoundKeys();
            var rt = new RoundTransmition();

            var cipher = new FeistelNetwork(rk, rt);

            var res = cipher.feistelNetwork(plainText, key);
            Console.WriteLine($"Перед шифрованием: {BitConverter.ToString(plainText)}");
            Console.WriteLine($"После шифрования: {BitConverter.ToString(res)}");
            Console.WriteLine(
                $"После дешифрования: {BitConverter.ToString(cipher.feistelNetworkRev(res, key))}"
            );
        }

        static void Main(String[] args)
        {
            TestFeistelConsistency1();
        }
    };
};
