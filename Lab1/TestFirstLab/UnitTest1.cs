using System.Text;

namespace TestFirstLab
{
    [TestFixture]
    public class CipheringIntegrationTests
    {
        private readonly byte[] _desKey = new byte[8]
        {
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        };
        private readonly byte[] _deal128Key = new byte[16]
        {
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x00,
        };
        private readonly byte[] _deal192Key = new byte[24]
        {
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x00,
        };
        private readonly byte[] _deal256Key = new byte[32]
        {
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        };

        [Test]
        public void Ciphering_DES_ECB_Zeros_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_desKey, CipheringMode.ECB, PaddingMode.Zeros);
        }

        [Test]
        public void Ciphering_DES_CBC_PKCS7_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_desKey, CipheringMode.CBC, PaddingMode.PKCS7);
        }

        [Test]
        public void Ciphering_DES_PCBC_ANSI_X923_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_desKey, CipheringMode.PCBC, PaddingMode.ANSI_X923);
        }

        [Test]
        public void Ciphering_DES_CFB_ISO10126_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_desKey, CipheringMode.CFB, PaddingMode.ISO10126);
        }

        [Test]
        public void Ciphering_DES_OFB_Zeros_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_desKey, CipheringMode.OFB, PaddingMode.Zeros);
        }

        [Test]
        public void Ciphering_DES_CTR_PKCS7_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_desKey, CipheringMode.CTR, PaddingMode.PKCS7);
        }

        [Test]
        public void Ciphering_DES_RandomDelta_ISO10126_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_desKey, CipheringMode.RandomDelta, PaddingMode.ISO10126);
        }

        [Test]
        public void Ciphering_DEAL128_ECB_Zeros_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_deal128Key, CipheringMode.ECB, PaddingMode.Zeros);
        }

        [Test]
        public void Ciphering_DEAL192_CBC_PKCS7_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_deal192Key, CipheringMode.CBC, PaddingMode.PKCS7);
        }

        [Test]
        public void Ciphering_DEAL256_PCBC_ANSI_X923_ShouldEncryptAndDecrypt()
        {
            TestCipheringCombination(_deal256Key, CipheringMode.PCBC, PaddingMode.ANSI_X923);
        }

        [Test]
        public void Ciphering_DES_AllPaddingModes_ShouldWork()
        {
            var paddingModes = new[]
            {
                PaddingMode.Zeros,
                PaddingMode.PKCS7,
                PaddingMode.ANSI_X923,
                PaddingMode.ISO10126,
            };
            var testData = new[]
            {
                Encoding.UTF8.GetBytes("Short"),
                Encoding.UTF8.GetBytes("Exactly8By"),
                Encoding.UTF8.GetBytes("Longer test data that exceeds block size"),
            };

            foreach (var paddingMode in paddingModes)
            {
                foreach (var data in testData)
                {
                    var ciphering = new Ciphering(new DES(_desKey), CipheringMode.CBC, paddingMode);
                    var encrypted = ciphering.cipherBlock(data);
                    var decrypted = ciphering.decipherBlock(encrypted);

                    Assert.That(
                        decrypted,
                        Is.EqualTo(data),
                        $"Failed with padding {paddingMode} and data length {data.Length}"
                    );
                }
            }
        }

        [Test]
        public void Ciphering_DES_AllCipherModes_ShouldWork()
        {
            var cipherModes = new[]
            {
                CipheringMode.ECB,
                CipheringMode.CBC,
                CipheringMode.PCBC,
                CipheringMode.CFB,
                CipheringMode.OFB,
                CipheringMode.CTR,
                CipheringMode.RandomDelta,
            };
            var testData = Encoding.UTF8.GetBytes("Test data for all modes");

            foreach (var cipherMode in cipherModes)
            {
                var ciphering = new Ciphering(new DES(_desKey), cipherMode, PaddingMode.PKCS7);
                var encrypted = ciphering.cipherBlock(testData);
                var decrypted = ciphering.decipherBlock(encrypted);

                Assert.That(
                    decrypted,
                    Is.EqualTo(testData),
                    $"Failed with cipher mode {cipherMode}"
                );
            }
        }

        [Test]
        public void Ciphering_DEAL_AllKeySizes_ShouldWork()
        {
            var keys = new[] { _deal128Key, _deal192Key, _deal256Key };
            var testData = Encoding.UTF8.GetBytes("Test data for DEAL with different key sizes");

            foreach (var key in keys)
            {
                var ciphering = new Ciphering(new DEAL(key), CipheringMode.CBC, PaddingMode.PKCS7);
                var encrypted = ciphering.cipherBlock(testData);
                var decrypted = ciphering.decipherBlock(encrypted);

                Assert.That(
                    decrypted,
                    Is.EqualTo(testData),
                    $"Failed with key size {key.Length} bytes"
                );
            }
        }

        [Test]
        public void Ciphering_EmptyData_ShouldHandleCorrectly()
        {
            var ciphering = new Ciphering(new DES(_desKey), CipheringMode.CBC, PaddingMode.PKCS7);
            var emptyData = Array.Empty<byte>();

            var encrypted = ciphering.cipherBlock(emptyData);
            var decrypted = ciphering.decipherBlock(encrypted);

            Assert.That(decrypted, Is.EqualTo(emptyData));
        }

        [Test]
        public void Ciphering_LargeData_ShouldEncryptAndDecrypt()
        {
            var largeData = new byte[10240];
            new Random().NextBytes(largeData); //генерация 10кб данных

            var ciphering = new Ciphering(
                new DEAL(_deal256Key),
                CipheringMode.CBC,
                PaddingMode.PKCS7
            );
            var encrypted = ciphering.cipherBlock(largeData);
            var decrypted = ciphering.decipherBlock(encrypted);

            Assert.That(decrypted, Is.EqualTo(largeData));
        }

        [Test]
        public void Ciphering_FileOperations_ShouldWork()
        {
            var testFilePath = "test_file.txt";
            var testContent = "This is a test file content for encryption/decryption testing";

            try
            {
                File.WriteAllText(testFilePath, testContent);

                var ciphering = new Ciphering(
                    new DES(_desKey),
                    CipheringMode.CBC,
                    PaddingMode.PKCS7
                );

                var encryptedFilePath = ciphering.cipherFile(testFilePath);
                Assert.That(encryptedFilePath, Is.Not.Null);
                Assert.That(File.Exists(encryptedFilePath!), Is.True);

                var decryptedFilePath = ciphering.decipherFile(encryptedFilePath!);
                Assert.That(decryptedFilePath, Is.Not.Null);
                Assert.That(File.Exists(decryptedFilePath!), Is.True);

                var decryptedContent = File.ReadAllText(decryptedFilePath!);
                Assert.That(decryptedContent, Is.EqualTo(testContent));
            }
            finally
            {
                if (File.Exists(testFilePath))
                    File.Delete(testFilePath);
                if (File.Exists(testFilePath + "Cip"))
                    File.Delete(testFilePath + "Cip");
                if (File.Exists(testFilePath + "CipDecip"))
                    File.Delete(testFilePath + "CipDecip");
            }
        }

        [Test]
        public void Ciphering_DifferentIV_ShouldProduceDifferentResults()
        {
            var testData = Encoding.UTF8.GetBytes("Test data for IV comparison");

            var ciphering1 = new Ciphering(new DES(_desKey), CipheringMode.CBC, PaddingMode.PKCS7);
            var encrypted1 = ciphering1.cipherBlock(testData);

            var differentIV = new byte[8];
            new Random().NextBytes(differentIV);
            var ciphering2 = new Ciphering(
                new DES(_desKey),
                CipheringMode.CBC,
                PaddingMode.PKCS7,
                differentIV
            );
            var encrypted2 = ciphering2.cipherBlock(testData);

            Assert.That(encrypted2, Is.Not.EqualTo(encrypted1));

            var decrypted1 = ciphering1.decipherBlock(encrypted1);
            var decrypted2 = ciphering2.decipherBlock(encrypted2);

            Assert.That(decrypted1, Is.EqualTo(testData));
            Assert.That(decrypted2, Is.EqualTo(testData));
        }

        private void TestCipheringCombination(
            byte[] key,
            CipheringMode cipherMode,
            PaddingMode paddingMode
        )
        {
            var testData = new[]
            {
                Encoding.UTF8.GetBytes("Short"),
                Encoding.UTF8.GetBytes("Medium length test data"),
                Encoding.UTF8.GetBytes(
                    "Very long test data that definitely exceeds one block size for any algorithm"
                ),
            };

            ICipheringAlgorithm algorithm = key.Length == 8 ? new DES(key) : new DEAL(key);

            foreach (var data in testData)
            {
                var ciphering = new Ciphering(algorithm, cipherMode, paddingMode);
                var encrypted = ciphering.cipherBlock(data);
                var decrypted = ciphering.decipherBlock(encrypted);

                Assert.That(
                    decrypted,
                    Is.EqualTo(data),
                    $"Failed with {algorithm.GetType().Name}, mode {cipherMode}, padding {paddingMode}, data length {data.Length}"
                );
            }
        }
    }
}
