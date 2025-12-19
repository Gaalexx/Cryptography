#region CipheringModes
namespace MyCiphering
{
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

            if (isFinalBlock && dataToCipher.Length % blockSize != 0)
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
            byte[] result = new byte[localDataTocipher.Length];
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

        public Task<byte[]> cipherAsync(byte[] dataToCipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => cipher(dataToCipher, IV, isFinalBlock));

        public Task<byte[]> decipherAsync(byte[] dataToDecipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => decipher(dataToDecipher, IV, isFinalBlock));
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

            if (isFinalBlock && dataToCipher.Length % blockSize != 0)
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
                    IVCopy[j] = (byte)(result[i + j] ^ blockToCipher[j]);
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

        public Task<byte[]> cipherAsync(byte[] dataToCipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => cipher(dataToCipher, IV, isFinalBlock));

        public Task<byte[]> decipherAsync(byte[] dataToDecipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => decipher(dataToDecipher, IV, isFinalBlock));
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
            if (isFinalBlock && dataToCipher.Length % blockSize != 0)
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

        public Task<byte[]> cipherAsync(byte[] dataToCipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => cipher(dataToCipher, IV, isFinalBlock));

        public Task<byte[]> decipherAsync(byte[] dataToDecipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => decipher(dataToDecipher, IV, isFinalBlock));
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
            if (isFinalBlock && dataToCipher.Length % blockSize != 0)
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

        public Task<byte[]> cipherAsync(byte[] dataToCipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => cipher(dataToCipher, IV, isFinalBlock));

        public Task<byte[]> decipherAsync(byte[] dataToDecipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => decipher(dataToDecipher, IV, isFinalBlock));
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
            if (isFinalBlock && dataToCipher.Length % blockSize != 0)
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

        public Task<byte[]> cipherAsync(byte[] dataToCipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => cipher(dataToCipher, IV, isFinalBlock));

        public Task<byte[]> decipherAsync(byte[] dataToDecipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => decipher(dataToDecipher, IV, isFinalBlock));
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
            if (isFinalBlock && dataToCipher.Length % blockSize != 0)
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
            return ProcessCTR(in localDataToDecipher, in IV, Mode.Decipher);
        }

        private byte[] ProcessCTR(in byte[] data, in byte[] IV, Mode mode)
        {
            int blockSize = cipheringAlgorithm.BlockSize;
            if (IV.Length != blockSize)
                throw new ArgumentException($"IV must be {blockSize} bytes ({blockSize * 8} bits)");

            byte[] result = new byte[data.Length];

            byte[] counter = (byte[])IV.Clone();

            for (int i = 0; i < result.Length; i += blockSize)
            {
                byte[] encryptedCounter = cipheringAlgorithm.cipherBlock(in counter);
                int currentBlockSize = Math.Min(blockSize, result.Length - i);

                for (int j = 0; j < currentBlockSize; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ encryptedCounter[j]);
                }

                IncrementCounter(counter);
            }

            return result;
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

        public Task<byte[]> cipherAsync(byte[] dataToCipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => cipher(dataToCipher, IV, isFinalBlock));

        public Task<byte[]> decipherAsync(byte[] dataToDecipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => decipher(dataToDecipher, IV, isFinalBlock));
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
            if (isFinalBlock && dataToCipher.Length % blockSize != 0)
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

            byte[] delta = (byte[])IV.Clone();

            for (int i = 0; i < result.Length; i += blockSize)
            {
                byte[] processedDelta = cipheringAlgorithm.cipherBlock(in delta);
                int currentBlockSize = Math.Min(blockSize, result.Length - i);

                for (int j = 0; j < currentBlockSize; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ processedDelta[j]);
                }

                AddLittleEndian(delta, processedDelta);
            }

            return result;
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

        public Task<byte[]> cipherAsync(byte[] dataToCipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => cipher(dataToCipher, IV, isFinalBlock));

        public Task<byte[]> decipherAsync(byte[] dataToDecipher, byte[] IV, bool isFinalBlock) =>
            Task.Run(() => decipher(dataToDecipher, IV, isFinalBlock));
    }
#endregion
}
