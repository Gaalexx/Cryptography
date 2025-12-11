using System;

namespace MyCiphering
{
    class TripleDes : ICipheringAlgorithm
    {
        public byte BlockSize { get; protected set; } = 8;
        protected DES[] desArray;

        public TripleDes(in byte[] key1, in byte[] key2, in byte[] key3)
        {
            desArray = new DES[3];
            desArray[0] = new DES(key1);
            desArray[1] = new DES(key2);
            desArray[2] = new DES(key3);
        }

        public byte[] cipherBlock(in byte[] blockToCipher)
        {
            byte[] result = (byte[])blockToCipher.Clone();

            result = desArray[0].cipherBlock(in result);
            result = desArray[1].decipherBlock(in result);
            result = desArray[2].cipherBlock(in result);

            return result;
        }

        public byte[] decipherBlock(in byte[] blockToDecipher)
        {
            byte[] result = (byte[])blockToDecipher.Clone();

            result = desArray[2].decipherBlock(in result);
            result = desArray[1].cipherBlock(in result);
            result = desArray[0].decipherBlock(in result);

            return result;
        }
    }
}
