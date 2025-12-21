using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using CipheringKeys;

namespace MyCiphering
{
    public class Ciphering
    {
        private ICipheringAlgorithm cipheringAlgorithm;
        private IPaddingMode paddingMode;
        private ICipheringMode cipheringMode;
        private readonly CipheringMode cipheringModeKind;
        private byte[] initializeVector;
        private readonly int bufferLength;

        public Ciphering(
            ICipheringAlgorithm cipheringAlgorithm,
            CipheringMode cipheringMode,
            PaddingMode paddingMode,
            byte[]? initializeVector = null
        )
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            this.cipheringModeKind = cipheringMode;
            bufferLength = cipheringAlgorithm.BlockSize * 512;
            if (initializeVector == null)
            {
                this.initializeVector = new byte[cipheringAlgorithm.BlockSize];
                Array.Fill<byte>(this.initializeVector, 0);
            }
            else
            {
                if (initializeVector.Length != this.cipheringAlgorithm.BlockSize)
                {
                    this.initializeVector = new byte[cipheringAlgorithm.BlockSize];
                    int delta = initializeVector.Length - cipheringAlgorithm.BlockSize;

                    if (delta < 0)
                    {
                        Array.Copy(
                            initializeVector,
                            this.initializeVector,
                            initializeVector.Length
                        );
                        for (int i = initializeVector.Length; i < -delta; i++)
                        {
                            this.initializeVector[i] = 0;
                        }
                    }
                    else
                    {
                        Array.Copy(
                            initializeVector,
                            this.initializeVector,
                            this.cipheringAlgorithm.BlockSize
                        );
                    }
                }
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

        public byte[] cipherArray(in byte[] bytes)
        {
            return cipheringMode.cipher(bytes, initializeVector, true);
        }

        public byte[] decipherArray(in byte[] bytes)
        {
            return cipheringMode.decipher(bytes, initializeVector, true);
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

        private byte[] UpdateIVForNextChunk(
            byte[] currentIV,
            byte[] input,
            byte[] output,
            bool isCipher
        )
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            int length = Math.Min(input.Length, output.Length);
            int blocks = length / blockSize;
            if (blocks == 0)
            {
                return currentIV;
            }

            switch (cipheringModeKind)
            {
                case CipheringMode.ECB:
                    return currentIV;
                case CipheringMode.CBC:
                case CipheringMode.CFB:
                    return CopyLastBlock(isCipher ? output : input, blockSize);
                case CipheringMode.PCBC:
                case CipheringMode.OFB:
                    return XorLastBlock(input, output, blockSize);
                case CipheringMode.CTR:
                    byte[] nextCounter = (byte[])currentIV.Clone();
                    IncrementCounterByBlocks(nextCounter, blocks);
                    return nextCounter;
                case CipheringMode.RandomDelta:
                    byte[] delta = (byte[])currentIV.Clone();
                    byte[] processedDelta = new byte[blockSize];
                    int processedLength = blocks * blockSize;
                    for (int i = 0; i < processedLength; i += blockSize)
                    {
                        for (int j = 0; j < blockSize; j++)
                        {
                            processedDelta[j] = (byte)(input[i + j] ^ output[i + j]);
                        }
                        AddLittleEndian(delta, processedDelta);
                    }
                    return delta;
                default:
                    return currentIV;
            }
        }

        private static byte[] CopyLastBlock(byte[] data, int blockSize)
        {
            if (data.Length < blockSize)
            {
                return (byte[])data.Clone();
            }
            byte[] block = new byte[blockSize];
            Array.Copy(data, data.Length - blockSize, block, 0, blockSize);
            return block;
        }

        private static byte[] XorLastBlock(byte[] left, byte[] right, int blockSize)
        {
            int leftStart = Math.Max(0, left.Length - blockSize);
            int rightStart = Math.Max(0, right.Length - blockSize);
            int length = Math.Min(
                blockSize,
                Math.Min(left.Length - leftStart, right.Length - rightStart)
            );
            byte[] block = new byte[blockSize];
            for (int i = 0; i < length; i++)
            {
                block[i] = (byte)(left[leftStart + i] ^ right[rightStart + i]);
            }
            return block;
        }

        private static void IncrementCounterByBlocks(byte[] counter, int blocks)
        {
            for (int i = 0; i < blocks; i++)
            {
                IncrementCounter(counter);
            }
        }

        private static void IncrementCounter(byte[] counter)
        {
            for (int i = 0; i < counter.Length; i++)
            {
                counter[i]++;
                if (counter[i] != 0)
                {
                    break;
                }
            }
        }

        private static void AddLittleEndian(byte[] target, byte[] addend)
        {
            int carry = 0;
            for (int i = 0; i < target.Length; i++)
            {
                int sum = target[i] + addend[i] + carry;
                target[i] = (byte)sum;
                carry = sum >> 8;
            }
        }

        public bool cipherFile(String pathToFile)
        {
            String newPath;
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }
            else
            {
                newPath = makeChangedFilePath(pathToFile, "Cip");
                byte[] buffer = new byte[bufferLength];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                byte[] currentIV = (byte[])this.initializeVector.Clone();
                using (FileStream fsW = new FileStream(newPath, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                            byte[] finalBlock = new byte[bytesRead];
                            Array.Copy(buffer, finalBlock, bytesRead);
                            cipheredBlockSizeBuffer = cipheringMode.cipher(
                                finalBlock,
                                currentIV,
                                isFinalBlock
                            );
                            fsW.Write(cipheredBlockSizeBuffer);
                            break;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.cipher(
                            buffer,
                            currentIV,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                        currentIV = UpdateIVForNextChunk(
                            currentIV,
                            buffer,
                            cipheredBlockSizeBuffer,
                            true
                        );
                    }
                }
            }
            return true;
        }

        public bool decipherFile(String pathToFile)
        {
            String newPath;
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }
            else
            {
                newPath = makeChangedFilePath(pathToFile, "Decip");
                byte[] buffer = new byte[bufferLength];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                byte[] currentIV = (byte[])this.initializeVector.Clone();
                using (FileStream fsW = new FileStream(newPath, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                            byte[] finalBlock = new byte[bytesRead];
                            Array.Copy(buffer, finalBlock, bytesRead);
                            cipheredBlockSizeBuffer = cipheringMode.decipher(
                                finalBlock,
                                currentIV,
                                isFinalBlock
                            );
                            fsW.Write(cipheredBlockSizeBuffer);
                            break;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.decipher(
                            buffer,
                            currentIV,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                        currentIV = UpdateIVForNextChunk(
                            currentIV,
                            buffer,
                            cipheredBlockSizeBuffer,
                            false
                        );
                    }
                }
            }
            return true;
        }

        public bool cipherFile(String pathToFile, String outputFile)
        {
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }
            else
            {
                byte[] buffer = new byte[bufferLength];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                byte[] currentIV = (byte[])this.initializeVector.Clone();
                using (FileStream fsW = new FileStream(outputFile, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                            byte[] finalBlock = new byte[bytesRead];
                            Array.Copy(buffer, finalBlock, bytesRead);
                            cipheredBlockSizeBuffer = cipheringMode.cipher(
                                finalBlock,
                                currentIV,
                                isFinalBlock
                            );
                            fsW.Write(cipheredBlockSizeBuffer);
                            break;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.cipher(
                            buffer,
                            currentIV,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                        currentIV = UpdateIVForNextChunk(
                            currentIV,
                            buffer,
                            cipheredBlockSizeBuffer,
                            true
                        );
                    }
                }
            }
            return true;
        }

        public bool decipherFile(String pathToFile, String outputFile)
        {
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }
            else
            {
                byte[] buffer = new byte[bufferLength];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                byte[] currentIV = (byte[])this.initializeVector.Clone();
                using (FileStream fsW = new FileStream(outputFile, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                            byte[] finalBlock = new byte[bytesRead];
                            Array.Copy(buffer, finalBlock, bytesRead);
                            cipheredBlockSizeBuffer = cipheringMode.decipher(
                                finalBlock,
                                currentIV,
                                isFinalBlock
                            );
                            fsW.Write(cipheredBlockSizeBuffer);
                            break;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.decipher(
                            buffer,
                            currentIV,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                        currentIV = UpdateIVForNextChunk(
                            currentIV,
                            buffer,
                            cipheredBlockSizeBuffer,
                            false
                        );
                    }
                }
            }
            return true;
        }

        public async Task<bool> cipherFileAsync(String pathToFile)
        {
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }

            String newPath = makeChangedFilePath(pathToFile, "Cip");
            byte[] buffer = new byte[bufferLength];
            byte[] currentIV = (byte[])this.initializeVector.Clone();
            using (FileStream fsW = new FileStream(newPath, FileMode.OpenOrCreate))
            using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
            {
                int bytesRead;
                while ((bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    bool isFinalBlock = fs.Position == fs.Length;
                    byte[] dataBlock = bytesRead < buffer.Length ? buffer[..bytesRead] : buffer;
                    byte[] cipheredBlock = await cipheringMode.cipherAsync(
                        dataBlock,
                        currentIV,
                        isFinalBlock
                    );
                    await fsW.WriteAsync(cipheredBlock, 0, cipheredBlock.Length);
                    if (!isFinalBlock)
                    {
                        currentIV = UpdateIVForNextChunk(currentIV, dataBlock, cipheredBlock, true);
                    }
                }
            }
            return true;
        }

        public async Task<bool> decipherFileAsync(String pathToFile)
        {
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }

            String newPath = makeChangedFilePath(pathToFile, "Decip");
            byte[] buffer = new byte[bufferLength];
            byte[] currentIV = (byte[])this.initializeVector.Clone();
            using (FileStream fsW = new FileStream(newPath, FileMode.OpenOrCreate))
            using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
            {
                int bytesRead;
                while ((bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    bool isFinalBlock = fs.Position == fs.Length;
                    byte[] dataBlock = bytesRead < buffer.Length ? buffer[..bytesRead] : buffer;
                    byte[] decipheredBlock = await cipheringMode.decipherAsync(
                        dataBlock,
                        currentIV,
                        isFinalBlock
                    );
                    await fsW.WriteAsync(decipheredBlock, 0, decipheredBlock.Length);
                    if (!isFinalBlock)
                    {
                        currentIV = UpdateIVForNextChunk(
                            currentIV,
                            dataBlock,
                            decipheredBlock,
                            false
                        );
                    }
                }
            }
            return true;
        }

        public async Task<bool> cipherFileAsync(String pathToFile, String outputFile)
        {
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }

            byte[] buffer = new byte[bufferLength];
            byte[] currentIV = (byte[])this.initializeVector.Clone();
            using (FileStream fsW = new FileStream(outputFile, FileMode.OpenOrCreate))
            using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
            {
                int bytesRead;
                while ((bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    bool isFinalBlock = fs.Position == fs.Length;
                    byte[] dataBlock = bytesRead < buffer.Length ? buffer[..bytesRead] : buffer;
                    byte[] cipheredBlock = await cipheringMode.cipherAsync(
                        dataBlock,
                        currentIV,
                        isFinalBlock
                    );
                    await fsW.WriteAsync(cipheredBlock, 0, cipheredBlock.Length);
                    if (!isFinalBlock)
                    {
                        currentIV = UpdateIVForNextChunk(currentIV, dataBlock, cipheredBlock, true);
                    }
                }
            }
            return true;
        }

        public async Task<bool> decipherFileAsync(String pathToFile, String outputFile)
        {
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }

            byte[] buffer = new byte[bufferLength];
            byte[] currentIV = (byte[])this.initializeVector.Clone();
            using (FileStream fsW = new FileStream(outputFile, FileMode.OpenOrCreate))
            using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
            {
                int bytesRead;
                while ((bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    bool isFinalBlock = fs.Position == fs.Length;
                    byte[] dataBlock = bytesRead < buffer.Length ? buffer[..bytesRead] : buffer;
                    byte[] decipheredBlock = await cipheringMode.decipherAsync(
                        dataBlock,
                        currentIV,
                        isFinalBlock
                    );
                    await fsW.WriteAsync(decipheredBlock, 0, decipheredBlock.Length);
                    if (!isFinalBlock)
                    {
                        currentIV = UpdateIVForNextChunk(
                            currentIV,
                            dataBlock,
                            decipheredBlock,
                            false
                        );
                    }
                }
            }
            return true;
        }
    }
}
