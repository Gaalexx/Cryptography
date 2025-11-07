namespace MyCiphering
{
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
}
