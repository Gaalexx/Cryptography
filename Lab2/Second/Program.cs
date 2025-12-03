using System;
using System.Diagnostics;
using System.Numerics;
using MathNet.Numerics;

namespace Program
{
    class Program
    {
        static void MeasureRSACreationTime()
        {
            int[] bitLengths = { 512, 1024, 2048, 3072 };

            foreach (int bitLen in bitLengths)
            {
                Stopwatch sw = Stopwatch.StartNew();
                RSA rsa = new RSA(SimplicityTestType.MillerRabin, 0.999, bitLen);
                sw.Stop();
                Console.WriteLine($"Bit length: {bitLen}, Time: {sw.ElapsedMilliseconds} ms");
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

            MeasureRSACreationTime();

            //RSA rsa = new RSA(SimplicityTestType.SolovayStrassen, 0.9, 3072);
            /* BigInteger bigInteger = BigInteger.Parse("152639512312312321313213");
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
