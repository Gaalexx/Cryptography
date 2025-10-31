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
            /* DEAL deal = new DEAL();
            byte[] data = new byte[]
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
            byte[] key = new byte[]
            {
                0x00,
                0x10,
                0x00,
                0x00,
                0x00,
                0x20,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            };
            var c = deal.cipherBlock(in data, in key);
            Console.WriteLine(BitConverter.ToString(c));
            var t = deal.decipherBlock(in c, in key);
            Console.WriteLine(BitConverter.ToString(t)); */

            DES des = new DES();
            ulong key = 123456789;
            Ciphering cipher = new Ciphering(
                BitConverter.GetBytes(key),
                des,
                CipheringMode.CBC,
                PaddingMode.PKCS7
            );
            cipher.cipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/test.txt");
            cipher.decipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/testCip.txt");
        }
    }
}
