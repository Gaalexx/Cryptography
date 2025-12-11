using System;

namespace Program
{
    class RC4
    {
        protected byte[] S;
        protected byte i,
            j;
        protected byte[] key;

        public RC4(byte[] key)
        {
            this.key = key;
            S = new byte[256];

            for (int k = 0; k < 256; k++)
            {
                S[k] = (byte)k;
            }

            int jLocal = 0;
            for (int k = 0; k < 256; k++)
            {
                jLocal = (jLocal + S[k] + key[k % key.Length]) & 0xFF;
                byte temp = S[k];
                S[k] = S[jLocal];
                S[jLocal] = temp;
            }

            i = 0;
            j = 0;
        }

        protected byte GetKeystreamByte()
        {
            i = (byte)((i + 1) & 0xFF);

            j = (byte)((j + S[i]) & 0xFF);

            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;

            int t = (S[i] + S[j]) & 0xFF;
            return S[t];
        }

        public byte[] Process(byte[] data)
        {
            byte[] output = new byte[data.Length];
            for (int k = 0; k < data.Length; k++)
            {
                byte keyByte = GetKeystreamByte();
                output[k] = (byte)(data[k] ^ keyByte);
            }
            return output;
        }

        public byte[] cipher(byte[] plaintext) => Process(plaintext);

        public byte[] decipher(byte[] ciphertext) => Process(ciphertext);
    }

    class Program
    {
        public static void Main(String[] args)
        {
            byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] plaintext = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

            RC4 rc4 = new RC4(key);

            Console.WriteLine($"Plaintext: {BitConverter.ToString(plaintext)}");

            var ciphertext = rc4.cipher(plaintext);
            Console.WriteLine($"Ciphertext: {BitConverter.ToString(ciphertext)}");

            RC4 rc4ForDecrypt = new RC4(key);
            var decrypted = rc4ForDecrypt.decipher(ciphertext);
            Console.WriteLine($"Decrypted: {BitConverter.ToString(decrypted)}");
        }
    }
}
