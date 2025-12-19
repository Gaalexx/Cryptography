using System;
using MathLab3;
using MyCiphering;

namespace AlgorithmLab3
{
    class RijndaelKeyGenerator : IGetRoundKeys
    {
        public byte RoundsAmount { get; private set; }
        public byte Nk { get; private set; }
        private readonly int Nb;
        private readonly ushort modPoly;
        private readonly byte[] sBox;

        public RijndaelKeyGenerator(
            in byte[] key,
            RijndaelBlockLength blockLength,
            ushort modPoly = GaluaField.ModPoly
        )
        {
            switch (key.Length)
            {
                case 16:
                {
                    break;
                }
                case 24:
                {
                    break;
                }
                case 32:
                {
                    break;
                }
                default:
                {
                    throw new ArgumentException("Длина ключа должна быть 128, 192 или 256 бит!");
                }
            }

            if (!GaluaField.IrreducibilityCheck(modPoly))
            {
                throw new ArgumentException("Модуль приводим над GF(2).", nameof(modPoly));
            }

            Nb = ((int)blockLength) / 4;
            Nk = (byte)(key.Length / 4);
            RoundsAmount = (byte)(Math.Max(Nb, Nk) + 6);
            this.modPoly = modPoly;
            sBox = RijndaelSBox.GetSBox(modPoly);
        }

        public byte[][] getRoundKeys(in byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.Length != Nk * 4)
            {
                throw new ArgumentException(
                    "Длина ключа не соответствует Nk, заданному в конструкторе."
                );
            }
            return ExpandKey(key);
        }

        private byte[][] ExpandKey(byte[] key)
        {
            int nbLocal = Nb;
            int nkLocal = Nk;
            int nr = RoundsAmount;

            int totalWords = nbLocal * (nr + 1);
            byte[] expanded = new byte[totalWords * 4];

            Array.Copy(key, expanded, key.Length);

            byte rcon = 0x01;
            byte[] temp = new byte[4];
            int iWord = nkLocal;

            while (iWord < totalWords)
            {
                for (int j = 0; j < 4; j++)
                    temp[j] = expanded[4 * (iWord - 1) + j];

                if (iWord % nkLocal == 0)
                {
                    RotWord(temp);
                    SubWord(temp);
                    temp[0] ^= rcon;

                    rcon = GaluaField.Multiplication(rcon, 0x02, modPoly);
                }
                else if (nkLocal > 6 && (iWord % nkLocal == 4))
                {
                    SubWord(temp);
                }

                for (int j = 0; j < 4; j++)
                {
                    expanded[4 * iWord + j] =
                        (byte)(expanded[4 * (iWord - nkLocal) + j] ^ temp[j]);
                }

                iWord++;
            }

            byte[][] roundKeys = new byte[nr + 1][];
            int roundKeySize = nbLocal * 4;
            for (int r = 0; r <= nr; r++)
            {
                roundKeys[r] = new byte[roundKeySize];
                Array.Copy(expanded, r * roundKeySize, roundKeys[r], 0, roundKeySize);
            }

            return roundKeys;
        }

        private static void RotWord(byte[] word)
        {
            byte t = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = t;
        }

        private void SubWord(byte[] word)
        {
            for (int i = 0; i < 4; i++)
            {
                word[i] = sBox[word[i]];
            }
        }
    }

    class RijndaelRoundTransmittion : IRoundTransmition
    {
        public byte RoundsAmount { get; private set; }
        private readonly byte[] sBox;
        private readonly byte[] invSBox;
        private readonly ushort modPoly;

        public RijndaelRoundTransmittion(
            in byte[] key,
            RijndaelBlockLength blockLength,
            ushort modPoly = GaluaField.ModPoly
        )
        {
            int nb = ((int)blockLength) / 4;
            int nk = key.Length / 4;

            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("Длина ключа должна быть 128, 192 или 256 бит!");

            RoundsAmount = (byte)(Math.Max(nb, nk) + 6);
            this.modPoly = modPoly;
            sBox = RijndaelSBox.GetSBox(modPoly);
            invSBox = RijndaelSBox.GetInvSBox(modPoly);
        }

        public byte[] roundTransmition(in byte[] bytes, in byte[] roundKey)
        {
            byte[] result = new byte[bytes.Length];

            // SubBytes
            for (int i = 0; i < bytes.Length; i++)
            {
                result[i] = sBox[bytes[i]];
            }

            int Nb = bytes.Length / 4; // количество столбцов: 4, 6 или 8

            // ShiftRows
            GaluaField.ShiftRows(result, Nb);

            // MixColumns
            GaluaField.MixColumns(result, Nb, modPoly);

            // AddRoundKey
            for (int i = 0; i < bytes.Length; i++)
            {
                result[i] ^= roundKey[i];
            }

            return result;
        }

        public byte[] roundTransmitionRev(in byte[] bytes, in byte[] roundKey)
        {
            byte[] result = new byte[bytes.Length];

            // AddRoundKey
            for (int i = 0; i < bytes.Length; i++)
            {
                result[i] = (byte)(bytes[i] ^ roundKey[i]);
            }

            int Nb = bytes.Length / 4; // количество столбцов: 4, 6 или 8

            // MixColumns^-1
            GaluaField.InvMixColumns(result, Nb, modPoly);

            // ShiftRows^-1
            GaluaField.InvShiftRows(result, Nb);

            // SubBytes^-1
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = invSBox[result[i]];
            }

            return result;
        }
    }

    class RijndaelWork
    {
        protected IGetRoundKeys getRoundKeys;
        protected IRoundTransmition roundTransmition;
        private byte[][] roundKeys;
        public byte BlockSize { get; private set; }
        protected byte[] sBox;
        protected byte[] invSBox;

        public RijndaelWork(
            IGetRoundKeys getRoundKeys,
            IRoundTransmition roundTransmition,
            in byte[] key,
            RijndaelBlockLength blockLength,
            ushort modPoly
        )
        {
            this.getRoundKeys = getRoundKeys;
            this.roundTransmition = roundTransmition;
            this.roundKeys = getRoundKeys.getRoundKeys(key);
            sBox = RijndaelSBox.GetSBox(modPoly);
            invSBox = RijndaelSBox.GetInvSBox(modPoly);

            switch (blockLength)
            {
                case RijndaelBlockLength.B128Bit:
                {
                    BlockSize = 16;
                    break;
                }
                case RijndaelBlockLength.B192Bit:
                {
                    BlockSize = 24;
                    break;
                }
                case RijndaelBlockLength.B256Bit:
                {
                    BlockSize = 32;
                    break;
                }
                default:
                {
                    throw new ArgumentException("Длина блока должна быть 128, 192 или 256 бит!");
                }
            }
        }

        public byte[] cipherBlock(in byte[] blockToCipher)
        {
            byte[] state = new byte[blockToCipher.Length];
            Array.Copy(blockToCipher, state, blockToCipher.Length);

            // начальный AddRoundKey (K0)
            for (int i = 0; i < state.Length; i++)
                state[i] ^= roundKeys[0][i];

            // полные раунды: 1..Nr-1
            for (int round = 1; round < roundTransmition.RoundsAmount; round++)
                state = roundTransmition.roundTransmition(state, roundKeys[round]);

            // последний раунд (без MixColumns) + ключ K_Nr
            for (int i = 0; i < state.Length; i++)
                state[i] = sBox[state[i]];

            int Nb = state.Length / 4;
            GaluaField.ShiftRows(state, Nb);

            for (int i = 0; i < state.Length; i++)
                state[i] ^= roundKeys[roundTransmition.RoundsAmount][i];

            return state;
        }

        public byte[] decipherBlock(in byte[] blockToDecipher)
        {
            byte[] state = new byte[blockToDecipher.Length];
            Array.Copy(blockToDecipher, state, blockToDecipher.Length);

            int Nb = state.Length / 4;
            int Nr = roundTransmition.RoundsAmount;

            // инвертируем последний раунд шифрования
            for (int i = 0; i < state.Length; i++)
                state[i] ^= roundKeys[Nr][i]; // AddRoundKey(K_Nr)

            GaluaField.InvShiftRows(state, Nb);

            for (int i = 0; i < state.Length; i++)
                state[i] = invSBox[state[i]];

            // раунды Nr-1 .. 1 (обратные полные раунды)
            for (int round = Nr - 1; round >= 1; round--)
                state = roundTransmition.roundTransmitionRev(state, roundKeys[round]);

            // финальный AddRoundKey(K0)
            for (int i = 0; i < state.Length; i++)
                state[i] ^= roundKeys[0][i];

            return state;
        }
    }

    public enum RijndaelBlockLength : byte
    {
        B128Bit = 16,
        B192Bit = 24,
        B256Bit = 32,
    }

    class Rijndael : RijndaelWork, ICipheringAlgorithm
    {
        public Rijndael(
            in byte[] key,
            RijndaelBlockLength blockLength = RijndaelBlockLength.B128Bit,
            ushort modPoly = GaluaField.ModPoly
        )
            : base(
                new RijndaelKeyGenerator(key, blockLength, modPoly),
                new RijndaelRoundTransmittion(key, blockLength, modPoly),
                key,
                blockLength,
                modPoly
            ) { }
    }
}
