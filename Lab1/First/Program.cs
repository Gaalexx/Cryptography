using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using CipheringKeys;
using MyCiphering;
using NUnit.Framework.Internal;

namespace Program
{
    class Program
    {
        static void testDesVariations()
        {
            DES des = new DES(BitConverter.GetBytes(123123123));

            Ciphering ciphering = new Ciphering(des, CipheringMode.PCBC, PaddingMode.Zeros);
            ciphering.cipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/test");
            ciphering.decipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/testCip");
            ciphering.cipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/test.png");
            ciphering.decipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/testCip.png");
        }

        static void testDealVariations()
        {
            byte[] key128 = BitConverter
                .GetBytes(12321323123123)
                .Concat(BitConverter.GetBytes(38254362842834))
                .ToArray();
            byte[] key192 = key128.Concat(BitConverter.GetBytes(21312312321312)).ToArray();
            byte[] key256 = key192.Concat(BitConverter.GetBytes(98798737456)).ToArray();

            DEAL deal = new DEAL(key256);

            Ciphering ciphering = new Ciphering(deal, CipheringMode.ECB, PaddingMode.Zeros);
            ciphering.cipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/test");
            ciphering.decipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/testCip");
            ciphering.cipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/test.png");
            ciphering.decipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/testCip.png");
        }

        static void Main(String[] args)
        {
            testDesVariations();
        }
    }
}
