namespace MyCiphering
{
    #region interfaces
    public interface ICipheringMode
    {
        public byte[] cipher(in byte[] dataToCipher, in byte[] IV, bool isFinalBlock);
        public byte[] decipher(in byte[] dataToDecipher, in byte[] IV, bool isFinalBlock);
        public Task<byte[]> cipherAsync(byte[] dataToCipher, byte[] IV, bool isFinalBlock);
        public Task<byte[]> decipherAsync(byte[] dataToDecipher, byte[] IV, bool isFinalBlock);
    }

    public interface IPaddingMode
    {
        public byte[] packMissingBytes(in byte[] bytes, int neededLength);
        public byte[] unpackMissingBytes(in byte[] bytes);
        //public byte[] unpackMissingBytes(in byte[] bytes, int neededLength);
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

    #endregion
}
