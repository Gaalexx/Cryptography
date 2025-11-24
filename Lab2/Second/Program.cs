using System;
using System.Numerics;
using MathNet.Numerics;

namespace Program
{
    class Program
    {
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

            RSA rsa = new RSA(SimplicityTestType.SolovayStrassen, 0.9, 128);
            BigInteger bigInteger = BigInteger.Parse("152639512312312321313213");
            BigInteger encrypted = rsa.encrypt(bigInteger);
            BigInteger decrypted = rsa.decrypt(encrypted);
            Console.WriteLine(encrypted);
            Console.WriteLine(decrypted);
            Console.WriteLine(bigInteger == decrypted);
        }
    }
}
