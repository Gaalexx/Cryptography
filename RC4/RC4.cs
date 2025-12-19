using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

        public void ProcessInPlace(Span<byte> data)
        {
            for (int k = 0; k < data.Length; k++)
            {
                data[k] ^= GetKeystreamByte();
            }
        }

        public async Task ProcessFileAsync(
            string inputFilePath,
            string outputFilePath,
            int bufferSize = 81920,
            CancellationToken cancellationToken = default
        )
        {
            var outputDirectory = Path.GetDirectoryName(Path.GetFullPath(outputFilePath));
            if (!string.IsNullOrWhiteSpace(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }

            await using var input = new FileStream(
                inputFilePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize,
                useAsync: true
            );
            await using var output = new FileStream(
                outputFilePath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize,
                useAsync: true
            );

            var buffer = new byte[bufferSize];
            int bytesRead;
            while (
                (
                    bytesRead = await input.ReadAsync(
                        buffer.AsMemory(0, buffer.Length),
                        cancellationToken
                    )
                ) > 0
            )
            {
                ProcessInPlace(buffer.AsSpan(0, bytesRead));
                await output.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
            }
        }

        public static bool RunSelfTest(TextWriter? log = null)
        {
            byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] plaintext = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] expectedCiphertext = { 0x75, 0xB7, 0x87, 0x80, 0x99, 0xE0, 0xC5, 0x96 };

            var encryptor = new RC4(key);
            var producedCiphertext = encryptor.cipher(plaintext);
            bool matchesCipher = producedCiphertext.SequenceEqual(expectedCiphertext);

            var decryptor = new RC4(key);
            var decryptedPlaintext = decryptor.decipher(expectedCiphertext);
            bool matchesPlaintext = decryptedPlaintext.SequenceEqual(plaintext);

            bool success = matchesCipher && matchesPlaintext;

            if (log != null)
            {
                log.WriteLine($"Self-test {(success ? "passed" : "failed")}.");
                if (!success)
                {
                    log.WriteLine(
                        $"Expected ciphertext: {BitConverter.ToString(expectedCiphertext)}"
                    );
                    log.WriteLine(
                        $"Produced ciphertext: {BitConverter.ToString(producedCiphertext)}"
                    );
                    log.WriteLine(
                        $"Decrypted plaintext: {BitConverter.ToString(decryptedPlaintext)}"
                    );
                }
            }

            return success;
        }
    }
}
