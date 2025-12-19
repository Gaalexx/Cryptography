using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using MathNet.Numerics;

namespace Program
{
    class Program
    {
        static void TestRSA()
        {
            Console.WriteLine("=== RSA Tests ===");

            RSA rsa = new RSA(SimplicityTestType.MillerRabin, 0.999, 2048);

            BigInteger[] testMessages =
            {   
                new BigInteger(42),
                new BigInteger(12345),
                BigInteger.Parse("12345132213123131231231231236789012999999345"),
            };

            foreach (var msg in testMessages)
            {
                BigInteger encrypted = rsa.encrypt(msg);
                BigInteger decrypted = rsa.decrypt(encrypted);
                bool passed = msg == decrypted;
                Console.WriteLine(
                    $"Message: {msg}, Decrypted: {decrypted}, Test: {(passed ? "PASSED" : "FAILED")}"
                );
            }
        }

        static void MeasureRSACreationTime()
        {
            int[] bitLengths = { 512, 1024, 2048, 3072 };
            SimplicityTestType[] types = new SimplicityTestType[]
            {
                SimplicityTestType.SolovayStrassen,
                SimplicityTestType.MillerRabin,
                SimplicityTestType.Ferma,
            };
            foreach (SimplicityTestType type in types)
            {
                foreach (int bitLen in bitLengths)
                {
                    Stopwatch sw = Stopwatch.StartNew();
                    RSA rsa = new RSA(type, 0.999, bitLen);
                    sw.Stop();
                    Console.WriteLine(
                        $"Simplicity test: {type.ToString()} Bit length: {bitLen}, Time: {sw.ElapsedMilliseconds} ms"
                    );
                }
            }
        }

        static void TestWienerAttack()
        {
            Console.WriteLine("\n=== Wiener Attack Test ===");
            VienerAttack va = new VienerAttack(90581, 17993);
            var res = va.attack();
            if (res != null)
            {
                Console.WriteLine(
                    $"Attack SUCCESS: d = {res.Value.d}, fi = {res.Value.fi}, fractions = {res.Value.factorialConvergents.Count}"
                );
            }
            else
            {
                Console.WriteLine("Attack FAILED");
            }
        }

        static void TestFileEncryption(string? sourceFile = null)
        {
            Console.WriteLine("\n=== File Encryption Test ===");

            string baseName = $"rsa_file_test_{Guid.NewGuid():N}";
            string encryptedPath = Path.Combine(Path.GetTempPath(), $"{baseName}.enc");
            string decryptedPath = Path.Combine(Path.GetTempPath(), $"{baseName}.dec");

            string inputPath;
            byte[] content;
            bool generatedInput = false;

            if (!string.IsNullOrWhiteSpace(sourceFile))
            {
                inputPath = sourceFile;
                try
                {
                    content = File.ReadAllBytes(inputPath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"File test result: FAILED (cannot read input file: {ex.Message})");
                    return;
                }
            }
            else
            {
                inputPath = Path.Combine(Path.GetTempPath(), $"{baseName}.bin");
                content = new byte[256];
                new Random(12345).NextBytes(content);
                File.WriteAllBytes(inputPath, content);
                generatedInput = true;
            }

            RSA rsa = new RSA(SimplicityTestType.MillerRabin, 0.999, 512);

            try
            {
                rsa.encryptFile(inputPath, encryptedPath);
                rsa.decryptFile(encryptedPath, decryptedPath);

                byte[] decrypted = File.ReadAllBytes(decryptedPath);
                bool passed = content.SequenceEqual(decrypted);
                Console.WriteLine($"File test result: {(passed ? "PASSED" : "FAILED")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"File test result: FAILED ({ex.Message})");
            }
            finally
            {
                foreach (var path in new[] { encryptedPath, decryptedPath })
                {
                    try
                    {
                        if (File.Exists(path))
                        {
                            File.Delete(path);
                        }
                    }
                    catch
                    {
                    }
                }
                if (generatedInput)
                {
                    try
                    {
                        if (File.Exists(inputPath))
                        {
                            File.Delete(inputPath);
                        }
                    }
                    catch
                    {
                    }
                }
            }
        }

        static void Main(String[] args)
        {
            /* Console.WriteLine(CryptographicMath.EuclideanAlgorithm(12123, 332));
            Console.WriteLine(CryptographicMath.ModularExponentiation(3, 5, 5));
            Console.WriteLine(CryptographicMath.YakobiSymbol(7, 15));

            SolovayStrassenTest solovayStrassenTest = new SolovayStrassenTest();
            MillerRabinTest millerRabin = new MillerRabinTest();
            FermaTest fermaTest = new FermaTest();
            Console.WriteLine(solovayStrassenTest.Test(BigInteger.Parse("15263953"), 0.75));
            Console.WriteLine(millerRabin.Test(BigInteger.Parse("15263953"), 0.75));
            Console.WriteLine(fermaTest.Test(BigInteger.Parse("15263953"), 0.75));

            TestRSA();

            MeasureRSACreationTime();

            TestWienerAttack(); */

            TestFileEncryption("/home/gaalex/MAI/5sem/Cryptography/Lab2/Second/test.txt");
        }
    }
}
