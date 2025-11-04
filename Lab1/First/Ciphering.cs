using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using CipheringKeys;
using NUnit.Framework.Constraints;

namespace MyCiphering
{
    #region interfaces
    public interface ICipheringMode
    {
        public byte[] cipher(in byte[] dataToCipher, in byte[] IV, bool isFinalBlock);
        public byte[] decipher(in byte[] dataToDecipher, in byte[] IV, bool isFinalBlock);
    }

    public interface IPaddingMode
    {
        public byte[] packMissingBytes(in byte[] bytes, int neededLength);
        public byte[] unpackMissingBytes(in byte[] bytes);
    }

    public interface IGetRoundKeys
    {
        public byte[][] getRoundKeys(in byte[] key);
    }

    public interface IRoundTransmition
    {
        public byte RoundsAmount { get; }
        public byte[] roundTransmition(in byte[] bytes, in byte[] roundKey);
        public byte[] roundTransmitionRev(in byte[] bytes, in byte[] roundKey);
    }

    public interface ICipheringAlgorithm
    {
        public byte BlockSize { get; }
        public byte[] cipherBlock(in byte[] blockToCipher);
        public byte[] decipherBlock(in byte[] blockToDecipher);
    }

    public interface IBlockCiphering
    {
        public byte[] cipherBlock(in byte[] bytes);
        public byte[] decipherBlock(in byte[] bytes);
    }

    public class Ciphering
    {
        private ICipheringAlgorithm cipheringAlgorithm;
        private IPaddingMode paddingMode;
        private ICipheringMode cipheringMode;
        private byte[] initializeVector;

        public Ciphering( //TODO: занести PaddingMode обратно в CipheringMode
            ICipheringAlgorithm cipheringAlgorithm,
            CipheringMode cipheringMode,
            PaddingMode paddingMode,
            byte[]? initializeVector = null
        )
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            if (initializeVector == null)
            {
                this.initializeVector = new byte[cipheringAlgorithm.BlockSize];
                Array.Fill<byte>(this.initializeVector, 0);
            }
            else
            {
                this.initializeVector = (byte[])initializeVector.Clone();
            }
            switch (paddingMode)
            {
                case PaddingMode.Zeros:
                    this.paddingMode = new ZeroesPaddingMode();
                    break;
                case PaddingMode.ANSI_X923:
                    this.paddingMode = new ANSI_X923PaddingMode();
                    break;
                case PaddingMode.PKCS7:
                    this.paddingMode = new PKCS7PaddingMode();
                    break;
                case PaddingMode.ISO10126:
                    this.paddingMode = new ISO10126PaddingMode();
                    break;
                default:
                    throw new Exception("Нет такого режима паддинга.");
            }

            switch (cipheringMode)
            {
                case CipheringMode.ECB:
                    this.cipheringMode = new ECBCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.CBC:
                    this.cipheringMode = new CBCCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.PCBC:
                    this.cipheringMode = new PCBCCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.CFB:
                    this.cipheringMode = new CFBCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.OFB:
                    this.cipheringMode = new OFBCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.CTR:
                    this.cipheringMode = new CTRCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.RandomDelta:
                    this.cipheringMode = new RandomDeltaCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                default:
                    throw new Exception("Нет такого режима шифрования!");
            }
        }

        public byte[] cipherBlock(in byte[] bytes)
        {
            return cipheringMode.cipher(in bytes, in initializeVector, true);
        }

        public byte[] decipherBlock(in byte[] bytes)
        {
            return cipheringMode.decipher(in bytes, in initializeVector, true);
        }

        public void cipherArray(in byte[] bytes, ref byte[] result) //TODO: передавать массив полностью в CipheringMode
        {
            byte[] cipheredBuffer;
            byte[] buffer = new byte[cipheringAlgorithm.BlockSize];
            for (int i = 0; i < bytes.Length; i += cipheringAlgorithm.BlockSize)
            {
                if (bytes.Length - i < cipheringAlgorithm.BlockSize)
                {
                    byte[] lessBuffer = new byte[bytes.Length - i];
                    Array.Copy(bytes, i, buffer, 0, bytes.Length - i);
                    cipheredBuffer = cipherBlock(
                        paddingMode.packMissingBytes(buffer, cipheringAlgorithm.BlockSize)
                    );
                    Array.Copy(cipheredBuffer, 0, result, i, cipheredBuffer.Length);
                    break;
                }
                Array.Copy(bytes, i, buffer, 0, cipheringAlgorithm.BlockSize);
                cipheredBuffer = cipherBlock(buffer);
                Array.Copy(cipheredBuffer, 0, result, i, cipheringAlgorithm.BlockSize);
            }
        }

        public void decipherArray(in byte[] bytes, ref byte[] result) //TODO: передавать массив полностью в CipheringMode
        {
            byte[] cipheredBuffer;
            byte[] buffer = new byte[cipheringAlgorithm.BlockSize];
            for (int i = 0; i < bytes.Length; i += cipheringAlgorithm.BlockSize)
            {
                if (bytes.Length - i < cipheringAlgorithm.BlockSize)
                {
                    byte[] lessBuffer = new byte[bytes.Length - i];
                    Array.Copy(bytes, i, buffer, 0, bytes.Length - i);
                    cipheredBuffer = cipherBlock(buffer);
                    cipheredBuffer = paddingMode.unpackMissingBytes(cipheredBuffer);
                    Array.Copy(cipheredBuffer, 0, result, i, cipheredBuffer.Length);
                    break;
                }
                Array.Copy(bytes, i, buffer, 0, cipheringAlgorithm.BlockSize);
                cipheredBuffer = decipherBlock(buffer);
                Array.Copy(cipheredBuffer, 0, result, i, cipheringAlgorithm.BlockSize);
            }
        }

        private String makeChangedFilePath(String path, String toAdd)
        {
            int index = path.LastIndexOf('.');
            String newPath;
            if (index != -1)
            {
                newPath = path.Substring(0, index) + toAdd + path.Substring(index);
            }
            else
            {
                newPath = path + toAdd;
            }
            return newPath;
        }

        public String? cipherFile(String pathToFile)
        {
            String newPath;
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return null;
            }
            else
            {
                newPath = makeChangedFilePath(pathToFile, "Cip");
                byte[] buffer = new byte[4096];
                byte[] blockSizeBuffer = new byte[cipheringAlgorithm.BlockSize];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                using (FileStream fsW = new FileStream(newPath, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0) //TODO: передавать массив полностью в CipheringMode.cipher
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.cipher(
                            buffer,
                            this.initializeVector,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                    }
                }
            }
            return newPath;
        }

        public String? decipherFile(String pathToFile)
        {
            String newPath;
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return null;
            }
            else
            {
                newPath = makeChangedFilePath(pathToFile, "Decip");
                byte[] buffer = new byte[4096];
                byte[] blockSizeBuffer = new byte[cipheringAlgorithm.BlockSize];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                using (FileStream fsW = new FileStream(newPath, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0) //TODO: передавать массив полностью в CipheringMode.decipher
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.decipher(
                            buffer,
                            this.initializeVector,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                    }
                }
            }
            return newPath;
        }
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
    public class ZeroesPaddingMode : IPaddingMode
    {
        public byte[] packMissingBytes(in byte[] bytes, int neededLength)
        {
            if (bytes.Length != neededLength)
            {
                byte[] result = new byte[neededLength];
                Array.Copy(bytes, result, bytes.Length);
                Array.Fill<byte>(result, 0, bytes.Length, neededLength - bytes.Length);
                return result;
            }
            return (byte[])bytes.Clone();
        }

        public byte[] unpackMissingBytes(in byte[] bytes)
        {
            int lastNonZeroIndex = bytes.Length - 1;
            while (lastNonZeroIndex >= 0 && bytes[lastNonZeroIndex] == 0)
            {
                lastNonZeroIndex--;
            }

            if (lastNonZeroIndex < 0)
            {
                return new byte[0];
            }

            byte[] result = new byte[lastNonZeroIndex + 1];
            Array.Copy(bytes, result, lastNonZeroIndex + 1);
            return result;
        }
    }

    public class ANSI_X923PaddingMode : IPaddingMode
    {
        public byte[] packMissingBytes(in byte[] bytes, int neededLength)
        {
            if (bytes.Length != neededLength)
            {
                byte[] result = new byte[neededLength];
                Array.Copy(bytes, result, bytes.Length);

                Array.Fill<byte>(result, 0, bytes.Length, neededLength - bytes.Length - 1);
                result[result.Length - 1] = (byte)(neededLength - bytes.Length);
                return result;
            }
            return (byte[])bytes.Clone();
        }

        public byte[] unpackMissingBytes(in byte[] bytes)
        {
            if (bytes.Length == 0)
            {
                return (byte[])bytes.Clone();
            }

            byte paddingLength = bytes[bytes.Length - 1];

            if (paddingLength == 0 || paddingLength > bytes.Length)
            {
                return (byte[])bytes.Clone();
            }

            for (int i = bytes.Length - paddingLength; i < bytes.Length - 1; i++)
            {
                if (bytes[i] != 0)
                {
                    return (byte[])bytes.Clone();
                }
            }

            byte[] result = new byte[bytes.Length - paddingLength];
            Array.Copy(bytes, result, bytes.Length - paddingLength);
            return result;
        }
    }

    public class PKCS7PaddingMode : IPaddingMode
    {
        public byte[] packMissingBytes(in byte[] bytes, int neededLength)
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
            return (byte[])bytes.Clone();
        }

        public byte[] unpackMissingBytes(in byte[] bytes)
        {
            if (bytes.Length == 0)
            {
                return (byte[])bytes.Clone();
            }

            byte paddingLength = bytes[bytes.Length - 1];

            if (paddingLength == 0 || paddingLength > bytes.Length)
            {
                return (byte[])bytes.Clone();
            }

            for (int i = bytes.Length - paddingLength; i < bytes.Length; i++)
            {
                if (bytes[i] != paddingLength)
                {
                    return bytes;
                }
            }

            byte[] result = new byte[bytes.Length - paddingLength];
            Array.Copy(bytes, result, bytes.Length - paddingLength);
            return result;
        }
    }

    public class ISO10126PaddingMode : IPaddingMode
    {
        public byte[] packMissingBytes(in byte[] bytes, int neededLength)
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
            return (byte[])bytes.Clone();
        }

        public byte[] unpackMissingBytes(in byte[] bytes)
        {
            if (bytes.Length == 0)
                return (byte[])bytes.Clone();

            byte paddingLength = bytes[bytes.Length - 1];

            if (paddingLength == 0 || paddingLength > bytes.Length)
            {
                return (byte[])bytes.Clone();
            }

            byte[] result = new byte[bytes.Length - paddingLength];
            Array.Copy(bytes, result, bytes.Length - paddingLength);
            return result;
        }
    }

    public enum PaddingMode : byte
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
            Permutations.bitPermutations(
                ref result,
                KeyArray.getIP(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );

            for (int i = 0; i < roundTransmittion.RoundsAmount; i++)
            {
                result = roundTransmittion.roundTransmition(in result, roundKeys[i]);
            }
            Permutations.bitPermutations(
                ref result,
                KeyArray.getIPRev(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );
            return result;
        }

        public byte[] feistelNetworkRev(in byte[] bytes)
        {
            byte[] result = (byte[])bytes.Clone();

            Permutations.bitPermutations(
                ref result,
                KeyArray.getIP(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );

            for (int i = roundTransmittion.RoundsAmount - 1; i >= 0; i--)
            {
                result = roundTransmittion.roundTransmitionRev(in result, roundKeys[i]);
            }

            Permutations.bitPermutations(
                ref result,
                KeyArray.getIPRev(),
                Permutations.StartIndex.First,
                Permutations.Endian.BigEndian
            );

            return result;
        }
    }

    #region CipheringModes
    class ECBCipheringMode : ICipheringMode
    {
        private ICipheringAlgorithm cipheringAlgorithm;

        private IPaddingMode paddingMode;

        public ECBCipheringMode(ICipheringAlgorithm cipheringAlgorithm, IPaddingMode paddingMode)
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            this.paddingMode = paddingMode;
        }

        public byte[] cipher(in byte[] dataToCipher, in byte[]? IV = null, bool isFinalBlock = true)
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            byte[] localDataTocipher;
            byte[] result = new byte[dataToCipher.Length];
            if (isFinalBlock && dataToCipher.Length != dataToCipher.Length / blockSize * blockSize)
            {
                localDataTocipher = paddingMode.packMissingBytes(
                    dataToCipher,
                    dataToCipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataTocipher = dataToCipher;
            }
            Parallel.For(
                0,
                result.Length / blockSize,
                blockIndex =>
                {
                    int i = blockIndex * blockSize;
                    byte[] blockToCipher = new byte[blockSize];
                    Array.Copy(localDataTocipher, i, blockToCipher, 0, blockSize);
                    byte[] encryptedBlock = cipheringAlgorithm.cipherBlock(blockToCipher);
                    Array.Copy(encryptedBlock, 0, result, i, blockSize);
                }
            );

            return result;
        }

        public byte[] decipher(
            in byte[] dataToDecipher,
            in byte[]? IV = null,
            bool isFinalBlock = true
        )
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            byte[] localData = dataToDecipher;

            byte[] result = new byte[dataToDecipher.Length];

            Parallel.For(
                0,
                result.Length / blockSize,
                blockIndex =>
                {
                    int i = blockIndex * blockSize;
                    byte[] blockToDecipher = new byte[blockSize];
                    Array.Copy(localData, i, blockToDecipher, 0, blockSize);
                    byte[] decryptedBlock = cipheringAlgorithm.decipherBlock(blockToDecipher);
                    Array.Copy(decryptedBlock, 0, result, i, blockSize);
                }
            );
            if (isFinalBlock)
            {
                return paddingMode.unpackMissingBytes(result);
            }
            return result;
        }
    }

    class PCBCCipheringMode : ICipheringMode
    {
        private ICipheringAlgorithm cipheringAlgorithm;
        private IPaddingMode paddingMode;

        public PCBCCipheringMode(ICipheringAlgorithm cipheringAlgorithm, IPaddingMode paddingMode)
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            this.paddingMode = paddingMode;
        }

        public byte[] cipher(in byte[] dataToCipher, in byte[] IV, bool isFinalBlock = true)
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            byte[] localDataToCipher;

            if (isFinalBlock && dataToCipher.Length != dataToCipher.Length / blockSize * blockSize)
            {
                localDataToCipher = paddingMode.packMissingBytes(
                    in dataToCipher,
                    dataToCipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataToCipher = dataToCipher;
            }

            byte[] result = new byte[localDataToCipher.Length];
            byte[] xoring = new byte[blockSize];
            byte[] blockToCipher = new byte[blockSize];

            byte[] IVCopy = (byte[])IV.Clone();

            for (int i = 0; i < result.Length; i += blockSize)
            {
                Array.Copy(localDataToCipher, i, blockToCipher, 0, blockSize);
                for (int j = 0; j < blockSize; j++)
                {
                    xoring[j] = (byte)(IVCopy[j] ^ blockToCipher[j]);
                }
                Array.Copy(cipheringAlgorithm.cipherBlock(in xoring), 0, result, i, blockSize);
                for (int j = 0; j < blockSize; j++)
                {
                    IVCopy[j] = (byte)(IVCopy[j] ^ blockToCipher[j]);
                }
            }

            return result;
        }

        public byte[] decipher(in byte[] dataToDecipher, in byte[] IV, bool isFinalBlock = true)
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            byte[] result = new byte[dataToDecipher.Length];
            byte[] xoring = new byte[blockSize];
            byte[] blockToDecipher = new byte[blockSize];
            byte[] decipheredData = new byte[blockSize];
            byte[] IVCopy = (byte[])IV.Clone();

            for (int i = 0; i < result.Length; i += blockSize)
            {
                Array.Copy(dataToDecipher, i, blockToDecipher, 0, blockSize);
                Array.Copy(
                    cipheringAlgorithm.decipherBlock(in blockToDecipher),
                    0,
                    decipheredData,
                    0,
                    blockSize
                );
                for (int j = 0; j < blockSize; j++)
                {
                    xoring[j] = (byte)(decipheredData[j] ^ IVCopy[j]);
                }
                Array.Copy(xoring, 0, result, i, blockSize);
                for (int j = 0; j < blockSize; j++)
                {
                    IVCopy[j] = (byte)(blockToDecipher[j] ^ xoring[j]);
                }
            }
            if (isFinalBlock)
            {
                return paddingMode.unpackMissingBytes(in result);
            }
            return result;
        }
    }

    class CBCCipheringMode : ICipheringMode
    {
        private ICipheringAlgorithm cipheringAlgorithm;
        private IPaddingMode paddingMode;

        public CBCCipheringMode(ICipheringAlgorithm cipheringAlgorithm, IPaddingMode paddingMode)
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            this.paddingMode = paddingMode;
        }

        public byte[] cipher(in byte[] dataToCipher, in byte[] IV, bool isFinalBlock = true)
        {
            int blockSize = cipheringAlgorithm.BlockSize;

            byte[] localDataToCipher;
            if (isFinalBlock && dataToCipher.Length != dataToCipher.Length / blockSize * blockSize)
            {
                localDataToCipher = paddingMode.packMissingBytes(
                    in dataToCipher,
                    dataToCipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataToCipher = dataToCipher;
            }

            byte[] result = new byte[localDataToCipher.Length];
            byte[] IVCopy = (byte[])IV.Clone();
            byte[] blockToCipher = new byte[blockSize];
            for (int i = 0; i < result.Length; i += blockSize)
            {
                Array.Copy(localDataToCipher, i, blockToCipher, 0, blockSize);
                for (int j = 0; j < blockSize; j++)
                {
                    blockToCipher[j] = (byte)(IVCopy[j] ^ blockToCipher[j]);
                }
                var fr = cipheringAlgorithm.cipherBlock(in blockToCipher);
                Array.Copy(fr, 0, result, i, blockSize);
                Array.Copy(fr, 0, IVCopy, 0, blockSize);
            }
            return result;
        }

        public byte[] decipher(in byte[] dataToDecipher, in byte[] IV, bool isFinalBlock = true)
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            byte[] localData = dataToDecipher;
            byte[] IVCopy = (byte[])IV.Clone();
            byte[] result = new byte[dataToDecipher.Length];

            Parallel.For(
                0,
                result.Length / blockSize,
                blockIndex =>
                {
                    int i = blockIndex * blockSize;
                    byte[] localForXor = new byte[blockSize];
                    byte[] localBlockToDecipher = new byte[blockSize];
                    Array.Copy(localData, i, localBlockToDecipher, 0, blockSize);

                    if (i > 0)
                    {
                        Array.Copy(localData, i - blockSize, localForXor, 0, blockSize);
                    }
                    else
                    {
                        Array.Copy(IVCopy, localForXor, blockSize);
                    }

                    byte[] decryptedBlock = cipheringAlgorithm.decipherBlock(
                        in localBlockToDecipher
                    );

                    for (int j = 0; j < blockSize; j++)
                    {
                        decryptedBlock[j] = (byte)(decryptedBlock[j] ^ localForXor[j]);
                    }

                    Array.Copy(decryptedBlock, 0, result, i, blockSize);
                }
            );
            if (isFinalBlock)
            {
                return paddingMode.unpackMissingBytes(in result);
            }
            return result;
        }
    }

    class CFBCipheringMode : ICipheringMode
    {
        private ICipheringAlgorithm cipheringAlgorithm;
        private IPaddingMode paddingMode;

        public CFBCipheringMode(ICipheringAlgorithm cipheringAlgorithm, IPaddingMode paddingMode)
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            this.paddingMode = paddingMode;
        }

        public byte[] cipher(in byte[] dataToCipher, in byte[] IV, bool isFinalBlock = true)
        {
            int blockSize = cipheringAlgorithm.BlockSize;

            byte[] localDataToCipher;
            if (isFinalBlock && dataToCipher.Length != dataToCipher.Length / blockSize * blockSize)
            {
                localDataToCipher = paddingMode.packMissingBytes(
                    in dataToCipher,
                    dataToCipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataToCipher = dataToCipher;
            }

            byte[] result = new byte[localDataToCipher.Length];
            byte[] Ci = (byte[])IV.Clone();
            byte[] xoring;
            byte[] blockToCipher = new byte[blockSize];
            for (int i = 0; i < result.Length; i += blockSize)
            {
                xoring = cipheringAlgorithm.cipherBlock(in Ci);
                Array.Copy(localDataToCipher, i, blockToCipher, 0, blockSize);
                for (int j = 0; j < blockSize; j++)
                {
                    result[i + j] = (byte)(blockToCipher[j] ^ xoring[j]);
                }
                Array.Copy(result, i, Ci, 0, blockSize);
            }
            return result;
        }

        public byte[] decipher(in byte[] dataToDecipher, in byte[] IV, bool isFinalBlock = true)
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            byte[] localData = dataToDecipher;
            byte[] IVCopy = IV;
            byte[] result = new byte[dataToDecipher.Length];

            Parallel.For(
                0,
                result.Length / blockSize,
                blockIndex =>
                {
                    int i = blockIndex * blockSize;
                    byte[] blockToDecipher = new byte[blockSize];
                    byte[] localXoring = new byte[blockSize];
                    Array.Copy(localData, i, blockToDecipher, 0, blockSize);
                    if (i > 0)
                    {
                        Array.Copy(localData, i - blockSize, localXoring, 0, blockSize);
                    }
                    else
                    {
                        Array.Copy(IVCopy, 0, localXoring, 0, blockSize);
                    }
                    var res = cipheringAlgorithm.cipherBlock(in localXoring);
                    for (int j = 0; j < blockSize; j++)
                    {
                        result[i + j] = (byte)(blockToDecipher[j] ^ res[j]);
                    }
                }
            );

            if (isFinalBlock)
            {
                return paddingMode.unpackMissingBytes(in result);
            }

            return result;
        }
    }

    class OFBCipheringMode : ICipheringMode
    {
        private enum Mode : byte
        {
            Cipher,
            Decipher,
        }

        private ICipheringAlgorithm cipheringAlgorithm;
        private IPaddingMode paddingMode;

        public OFBCipheringMode(ICipheringAlgorithm cipheringAlgorithm, IPaddingMode paddingMode)
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            this.paddingMode = paddingMode;
        }

        public byte[] cipher(in byte[] dataToCipher, in byte[] IV, bool isFinalBlock = true)
        {
            byte[] localDataToCipher;
            int blockSize = cipheringAlgorithm.BlockSize;
            if (isFinalBlock && dataToCipher.Length != dataToCipher.Length / blockSize * blockSize)
            {
                localDataToCipher = paddingMode.packMissingBytes(
                    in dataToCipher,
                    dataToCipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataToCipher = dataToCipher;
            }
            return processOFB(in localDataToCipher, in IV, Mode.Cipher);
        }

        public byte[] decipher(in byte[] dataToDecipher, in byte[] IV, bool isFinalBlock = true)
        {
            byte[] localDataToDecipher;
            int blockSize = cipheringAlgorithm.BlockSize;
            if (
                isFinalBlock
                && dataToDecipher.Length != dataToDecipher.Length / blockSize * blockSize
            )
            {
                localDataToDecipher = paddingMode.packMissingBytes(
                    in dataToDecipher,
                    dataToDecipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataToDecipher = dataToDecipher;
            }
            if (isFinalBlock)
            {
                return paddingMode.unpackMissingBytes(
                    processOFB(in localDataToDecipher, in IV, Mode.Decipher)
                );
            }
            return processOFB(in localDataToDecipher, in IV, Mode.Decipher);
        }

        private byte[] processOFB(in byte[] data, in byte[] IV, Mode mode)
        {
            int blockSize = cipheringAlgorithm.BlockSize;

            byte[] result = new byte[data.Length];

            byte[] Ek = (byte[])IV.Clone();
            byte[] dataBloc = new byte[blockSize];
            for (int i = 0; i < result.Length; i += blockSize)
            {
                Array.Copy(data, i, dataBloc, 0, blockSize);
                Ek = cipheringAlgorithm.cipherBlock(in Ek);
                for (int j = 0; j < blockSize; j++)
                {
                    result[i + j] = (byte)(dataBloc[j] ^ Ek[j]);
                }
            }

            return result;
        }
    }

    class CTRCipheringMode : ICipheringMode
    {
        private enum Mode : byte
        {
            Cipher,
            Decipher,
        }

        private ICipheringAlgorithm cipheringAlgorithm;
        private IPaddingMode paddingMode;

        public CTRCipheringMode(ICipheringAlgorithm cipheringAlgorithm, IPaddingMode paddingMode)
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            this.paddingMode = paddingMode;
        }

        public byte[] cipher(in byte[] dataToCipher, in byte[] IV, bool isFinalBlock = true)
        {
            byte[] localDataToCipher;
            int blockSize = cipheringAlgorithm.BlockSize;
            if (isFinalBlock && dataToCipher.Length != dataToCipher.Length / blockSize * blockSize)
            {
                localDataToCipher = paddingMode.packMissingBytes(
                    in dataToCipher,
                    dataToCipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataToCipher = dataToCipher;
            }
            return ProcessCTR(in localDataToCipher, in IV, Mode.Cipher);
        }

        public byte[] decipher(in byte[] dataToDecipher, in byte[] IV, bool isFinalBlock = true)
        {
            byte[] localDataToDecipher;
            int blockSize = cipheringAlgorithm.BlockSize;
            if (
                isFinalBlock
                && dataToDecipher.Length != dataToDecipher.Length / blockSize * blockSize
            )
            {
                localDataToDecipher = paddingMode.packMissingBytes(
                    in dataToDecipher,
                    dataToDecipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataToDecipher = dataToDecipher;
            }
            if (isFinalBlock)
            {
                return paddingMode.unpackMissingBytes(
                    ProcessCTR(in localDataToDecipher, in IV, Mode.Decipher)
                );
            }
            return ProcessCTR(in dataToDecipher, in IV, Mode.Decipher);
        }

        private byte[] ProcessCTR(in byte[] data, in byte[] IV, Mode mode)
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            if (IV.Length != blockSize)
                throw new ArgumentException($"IV must be {blockSize} bytes ({blockSize * 8} bits)");

            byte[] result = new byte[data.Length];

            ulong counter = BitConverter.ToUInt64(IV, 0);

            for (int i = 0; i < result.Length; i += blockSize)
            {
                byte[] counterBlock = BitConverter.GetBytes(counter);
                byte[] encryptedCounter = cipheringAlgorithm.cipherBlock(in counterBlock);

                int currentBlockSize = Math.Min(blockSize, result.Length - i);

                for (int j = 0; j < currentBlockSize; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ encryptedCounter[j % 8]); //TODO: другой тип для counter
                }

                counter++;
            }

            return result;
        }
    }

    class RandomDeltaCipheringMode : ICipheringMode
    {
        private enum Mode : byte
        {
            Cipher,
            Decipher,
        }

        private ICipheringAlgorithm cipheringAlgorithm;
        private IPaddingMode paddingMode;

        public RandomDeltaCipheringMode(
            ICipheringAlgorithm cipheringAlgorithm,
            IPaddingMode paddingMode
        )
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            this.paddingMode = paddingMode;
        }

        public byte[] cipher(in byte[] dataToCipher, in byte[] IV, bool isFinalBlock = true)
        {
            byte[] localDataToCipher;
            int blockSize = cipheringAlgorithm.BlockSize;
            if (isFinalBlock && dataToCipher.Length != dataToCipher.Length / blockSize * blockSize)
            {
                localDataToCipher = paddingMode.packMissingBytes(
                    in dataToCipher,
                    dataToCipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataToCipher = dataToCipher;
            }
            return ProcessRandomDelta(in localDataToCipher, in IV, Mode.Cipher);
        }

        public byte[] decipher(in byte[] dataToDecipher, in byte[] IV, bool isFinalBlock = true)
        {
            byte[] localDataToDecipher;
            int blockSize = cipheringAlgorithm.BlockSize;
            if (
                isFinalBlock
                && dataToDecipher.Length != dataToDecipher.Length / blockSize * blockSize
            )
            {
                localDataToDecipher = paddingMode.packMissingBytes(
                    in dataToDecipher,
                    dataToDecipher.Length / blockSize * blockSize + blockSize
                );
            }
            else
            {
                localDataToDecipher = dataToDecipher;
            }
            if (isFinalBlock)
            {
                return paddingMode.unpackMissingBytes(
                    ProcessRandomDelta(in localDataToDecipher, in IV, Mode.Decipher)
                );
            }
            return ProcessRandomDelta(in localDataToDecipher, in IV, Mode.Decipher);
        }

        private byte[] ProcessRandomDelta(
            in byte[] data,
            in byte[] IV,
            Mode mode,
            bool isFinalBlock = true
        )
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            if (IV.Length != blockSize)
                throw new ArgumentException($"IV must be {blockSize} bytes ({blockSize * 8} bits)");

            byte[] result = new byte[data.Length];

            ulong delta = BitConverter.ToUInt64(IV, 0);

            for (int i = 0; i < result.Length; i += blockSize)
            {
                byte[] deltaBlock = BitConverter.GetBytes(delta);
                byte[] processedDelta = cipheringAlgorithm.cipherBlock(in deltaBlock);

                int currentBlockSize = Math.Min(blockSize, result.Length - i);

                for (int j = 0; j < currentBlockSize; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ processedDelta[j]);
                }

                ulong deltaIncrement = BitConverter.ToUInt64(processedDelta, 0);
                delta += deltaIncrement;
            }

            return result;
        }
    }
    #endregion


    public class DES : FeistelNetwork, ICipheringAlgorithm
    {
        public byte BlockSize { get; private set; } = 8;

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

    public class DEALRoundKeys : IGetRoundKeys
    {
        public byte[][] getRoundKeys(in byte[] key)
        {
            byte[][] keyBlocks;
            byte keyBlocksAmount = (byte)(key.Length / 8);
            byte[] KKey = BitConverter.GetBytes(0x0123456789abcdef);

            keyBlocks = new byte[keyBlocksAmount][];
            for (int i = 0; i < keyBlocksAmount; i++)
            {
                keyBlocks[i] = new byte[8];
                for (int j = 0; j < 8; j++)
                {
                    keyBlocks[i][j] = key[i * 8 + j];
                }
            }
            switch (key.Length)
            {
                case 16:
                {
                    return roundsFor128BitKey(in KKey, in keyBlocks);
                }
                case 24:
                {
                    return roundsFor192BitKey(in KKey, in keyBlocks);
                }
                case 32:
                {
                    return roundsFor256BitKey(in KKey, in keyBlocks);
                }
                default:
                {
                    throw new Exception("Длина ключа должна быть 16, 24 ил 32 байта");
                }
            }
        }

        private byte[][] roundsFor128BitKey(in byte[] KKey, in byte[][] keyBlocks)
        {
            CBCCipheringMode cbc = new CBCCipheringMode(new DES(KKey), new ZeroesPaddingMode());
            byte[] IV = new byte[8] { 0, 0, 0, 0, 0, 0, 0, 0 };

            byte[][] roundKeys = new byte[6][];

            //первый раунд
            roundKeys[0] = cbc.cipher(in keyBlocks[0], IV);

            //второй раунд
            byte[] blockToCipher = new byte[8];
            for (int j = 0; j < 8; j++)
            {
                blockToCipher[j] = (byte)(keyBlocks[1][j] ^ roundKeys[0][j]);
            }
            roundKeys[1] = cbc.cipher(in blockToCipher, IV);

            //остальные раунды
            for (int i = 2; i < 6; i++)
            {
                byte[] upperBit = BitConverter.GetBytes(0x8000000000000000 / (ulong)(1 << (i - 2)));
                for (int j = 0; j < 8; j++)
                {
                    blockToCipher[j] = (byte)(
                        keyBlocks[i % 2][j] ^ roundKeys[i - 1][j] ^ upperBit[j]
                    );
                }
                roundKeys[i] = cbc.cipher(in blockToCipher, IV);
            }
            return roundKeys;
        }

        private byte[][] roundsFor192BitKey(in byte[] KKey, in byte[][] keyBlocks)
        {
            CBCCipheringMode cbc = new CBCCipheringMode(new DES(KKey), new ZeroesPaddingMode());
            byte[] IV = new byte[8] { 0, 0, 0, 0, 0, 0, 0, 0 };

            byte[][] roundKeys = new byte[6][];

            //первый раунд
            roundKeys[0] = cbc.cipher(in keyBlocks[0], IV);

            byte[] blockToCipher = new byte[8];
            //второй и третий раунды
            for (int i = 1; i < 3; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    blockToCipher[j] = (byte)(keyBlocks[i % 3][j] ^ roundKeys[i - 1][j]);
                }
                roundKeys[i] = cbc.cipher(in blockToCipher, IV);
            }

            //остальные раунды
            for (int i = 3; i < 6; i++)
            {
                byte[] upperBit = BitConverter.GetBytes(0x8000000000000000 / (ulong)(1 << (i - 3)));
                for (int j = 0; j < 8; j++)
                {
                    blockToCipher[j] = (byte)(
                        keyBlocks[i % 3][j] ^ roundKeys[i - 1][j] ^ upperBit[j]
                    );
                }
                roundKeys[i] = cbc.cipher(in blockToCipher, IV);
            }
            return roundKeys;
        }

        private byte[][] roundsFor256BitKey(in byte[] KKey, in byte[][] keyBlocks)
        {
            CBCCipheringMode cbc = new CBCCipheringMode(new DES(KKey), new ZeroesPaddingMode());
            byte[] IV = new byte[8] { 0, 0, 0, 0, 0, 0, 0, 0 };

            byte[][] roundKeys = new byte[6][];

            //первый раунд
            roundKeys[0] = cbc.cipher(in keyBlocks[0], IV);

            byte[] blockToCipher = new byte[8];
            //второй - четвертый раунды
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    blockToCipher[j] = (byte)(keyBlocks[i % 4][j] ^ roundKeys[i - 1][j]);
                }
                roundKeys[i] = cbc.cipher(in blockToCipher, IV);
            }

            //остальные раунды
            for (int i = 4; i < 8; i++)
            {
                byte[] upperBit = BitConverter.GetBytes(0x8000000000000000 / (ulong)(1 << (i - 4)));
                for (int j = 0; j < 8; j++)
                {
                    blockToCipher[j] = (byte)(
                        keyBlocks[i % 4][j] ^ roundKeys[i - 1][j] ^ upperBit[j]
                    );
                }
                roundKeys[i] = cbc.cipher(in blockToCipher, IV);
            }
            return roundKeys;
        }
    }

    public class DEALRoundTransmittion : IRoundTransmition
    {
        public byte RoundsAmount { get; set; }
        private ECBCipheringMode? eccCM;

        public DEALRoundTransmittion(byte[] key)
        {
            switch (key.Length)
            {
                case 16:
                {
                    RoundsAmount = 6;
                    break;
                }
                case 24:
                {
                    RoundsAmount = 6;
                    break;
                }
                case 32:
                {
                    RoundsAmount = 8;
                    break;
                }
                default:
                {
                    throw new Exception("Длина ключа должна быть 128, 192 или 256 бит!");
                }
            }
        }

        public byte[] roundTransmition(in byte[] bytes, in byte[] roundKey)
        {
            eccCM = new ECBCipheringMode(new DES(roundKey), new ZeroesPaddingMode());
            byte[] left = new byte[4];
            byte[] right = new byte[4];

            Array.Copy(bytes, 0, left, 0, 4);
            Array.Copy(bytes, 4, right, 0, 4);

            byte[] feistelResult = eccCM.cipher(in right);

            byte[] newRight = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                newRight[i] = (byte)(left[i] ^ feistelResult[i]);
            }

            return right.Concat(newRight).ToArray();
        }

        public byte[] roundTransmitionRev(in byte[] bytes, in byte[] roundKey)
        {
            eccCM = new ECBCipheringMode(new DES(roundKey), new ZeroesPaddingMode());
            byte[] left = new byte[4];
            byte[] right = new byte[4];

            Array.Copy(bytes, 0, left, 0, 4);
            Array.Copy(bytes, 4, right, 0, 4);

            byte[] feistelResult = eccCM.cipher(in left);

            byte[] originalRight = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                originalRight[i] = (byte)(right[i] ^ feistelResult[i]);
            }

            return originalRight.Concat(left).ToArray();
        }
    }

    public class DEAL : DES, ICipheringAlgorithm
    {
        public new byte BlockSize { get; private set; } = 16;

        public DEAL(byte[] key)
            : base(key, new DEALRoundKeys(), new DEALRoundTransmittion(key)) { }

        public DEAL(byte[] key, IGetRoundKeys getRoundKeys, IRoundTransmition roundTransmition)
            : base(key, getRoundKeys, roundTransmition) { }

        public override byte[] cipherBlock(in byte[] blockToCipher)
        {
            return feistelNetwork(blockToCipher);
        }

        public override byte[] decipherBlock(in byte[] blockToDecipher)
        {
            return feistelNetworkRev(blockToDecipher);
        }
    }
}
