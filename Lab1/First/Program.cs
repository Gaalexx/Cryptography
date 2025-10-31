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
        static void Main(String[] args)
        {
            DES des = new DES();
            ulong key = 123456789;
            Ciphering cipher = new Ciphering(
                BitConverter.GetBytes(key),
                des,
                CipheringMode.ECB,
                PaddingMode.PKCS7
            );
            cipher.cipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/test.png");
            cipher.decipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/testCip.png");
        }
    }
}
