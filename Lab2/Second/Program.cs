using System;
using System.Numerics;
using MathNet.Numerics;

namespace Program
{
    class Program
    {
        static void Main(String[] args)
        {
            Console.WriteLine(CryptographicMath.EuclideanAlgorithm(12123, 332));
            Console.WriteLine(CryptographicMath.ModularExponentiation(3, 5, 5));
            Console.WriteLine(CryptographicMath.YakobiSymbol(7, 15));

            SolovayStrassenTest solovayStrassenTest = new SolovayStrassenTest();
            MillerRabin millerRabin = new MillerRabin();
            FermaTest fermaTest = new FermaTest();
            Console.WriteLine(solovayStrassenTest.Test(BigInteger.Parse("15263953"), 0.75));
            Console.WriteLine(millerRabin.Test(BigInteger.Parse("15263953"), 0.75));
            Console.WriteLine(fermaTest.Test(BigInteger.Parse("15263953"), 0.75));
        }
    }
}
