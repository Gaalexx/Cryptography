namespace MyCiphering
{
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

            byte[][] roundKeys = new byte[8][];

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

        //private ECBCipheringMode? eccCM;
        //private Mutex mutex;

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
            var eccCM = new ECBCipheringMode(new DES(roundKey), new ZeroesPaddingMode());
            byte[] left = new byte[8];
            byte[] right = new byte[8];

            Array.Copy(bytes, 0, left, 0, 8);
            Array.Copy(bytes, 8, right, 0, 8);

            byte[] feistelResult = eccCM.cipher(in right);

            byte[] newRight = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                newRight[i] = (byte)(left[i] ^ feistelResult[i]);
            }
            return right.Concat(newRight).ToArray();
        }

        public byte[] roundTransmitionRev(in byte[] bytes, in byte[] roundKey)
        {
            var eccCM = new ECBCipheringMode(new DES(roundKey), new ZeroesPaddingMode());
            byte[] left = new byte[8];
            byte[] right = new byte[8];

            Array.Copy(bytes, 0, left, 0, 8);
            Array.Copy(bytes, 8, right, 0, 8);

            byte[] feistelResult = eccCM.cipher(in left);

            byte[] originalRight = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                originalRight[i] = (byte)(right[i] ^ feistelResult[i]);
            }
            return originalRight.Concat(left).ToArray();
        }
    }

    public class DEAL : DES, ICipheringAlgorithm
    {
        public DEAL(byte[] key)
            : base(key, new DEALRoundKeys(), new DEALRoundTransmittion(key))
        {
            BlockSize = 16;
        }

        public DEAL(byte[] key, IGetRoundKeys getRoundKeys, IRoundTransmition roundTransmition)
            : base(key, getRoundKeys, roundTransmition)
        {
            BlockSize = 16;
        }

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
