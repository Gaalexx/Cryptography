using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Program
{
    class Program
    {
        private const string InputFile = "input.txt";
        private const string EncryptedFile = "encrypted.bin";
        private const string DecryptedFile = "decrypted.bin";
        private const string KeyValue = "0x0123456789ABCDEF";

        public static async Task<int> Main()
        {
            if (!RunTest())
            {
                Console.Error.WriteLine("Self-test failed. Aborting.");
                return 1;
            }

            if (!File.Exists(InputFile))
            {
                var sampleText = $"Sample RC4 input generated at {DateTime.UtcNow:O}";
                File.WriteAllText(InputFile, sampleText, Encoding.UTF8);
            }

            byte[] key;
            if (KeyValue.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                string hex = KeyValue.Substring(2);
                if (hex.Length % 2 != 0)
                {
                    throw new ArgumentException("Hex key length must be even.");
                }

                key = new byte[hex.Length / 2];
                for (int i = 0; i < key.Length; i++)
                {
                    key[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                }
            }
            else
            {
                key = Encoding.UTF8.GetBytes(KeyValue);
            }

            var encryptor = new RC4(key);
            await encryptor.ProcessFileAsync(InputFile, EncryptedFile);

            var decryptor = new RC4(key);
            await decryptor.ProcessFileAsync(EncryptedFile, DecryptedFile);
            return 0;
        }

        private static bool RunTest() => RC4.RunSelfTest();
    }
}
