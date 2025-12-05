using System;
using System.Diagnostics;
using System.Numerics;
using MathNet.Numerics;

namespace Program
{
    class Program
    {
        static void TestRSA()
        {
            Console.WriteLine("=== RSA Tests ===");

            RSA rsa = new RSA(SimplicityTestType.MillerRabin, 0.999, 512);

            BigInteger[] testMessages =
            {
                new BigInteger(42),
                new BigInteger(12345),
                BigInteger.Parse("123456789012345"),
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
            Console.WriteLine(fermaTest.Test(BigInteger.Parse("15263953"), 0.75)); */
            //TestRSA();

            MeasureRSACreationTime();

            /* RSA rsa = new RSA(SimplicityTestType.SolovayStrassen, 0.9, 1024);
            BigInteger bigInteger = BigInteger.Parse("152639512312312321313213");
            BigInteger encrypted = rsa.encrypt(bigInteger);
            BigInteger decrypted = rsa.decrypt(encrypted);
            Console.WriteLine(encrypted);
            Console.WriteLine(decrypted);
            Console.WriteLine(bigInteger == decrypted); */

            /* VienerAttack va = new VienerAttack(90581, 17993);
            var res = va.attack();
            if (res != null)
            {
                Console.WriteLine(
                    $"d = {res.Value.d}\nfi = {res.Value.fi}\nfractions amount = {res.Value.factorialConvergents.Count}"
                );
            }
            else
            {
                Console.WriteLine("Attack failed");
            } */
        }
    }
}
