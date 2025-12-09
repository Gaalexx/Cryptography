using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using AlgorithmLab3;
using CipheringKeys;
using MyCiphering;

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

        private static String makeChangedFilePath(String path, String toAdd)
        {
            int index = path.LastIndexOf('.');
            String newPath;
            if (index != -1)
            {
                newPath = path.Substring(0, index) + toAdd + path.Substring(index);
            }
            else
            {
                newPath = path + toAdd;
            }
            return newPath;
        }

        public static bool filesAreEqual(string filePath1, string filePath2)
        {
            if (!File.Exists(filePath1) || !File.Exists(filePath2))
                return false;

            FileInfo file1 = new FileInfo(filePath1);
            FileInfo file2 = new FileInfo(filePath2);

            if (file1.Length != file2.Length)
                return false;

            const int bufferSize = 4096;
            byte[] buffer1 = new byte[bufferSize];
            byte[] buffer2 = new byte[bufferSize];

            using (var stream1 = new FileStream(filePath1, FileMode.Open, FileAccess.Read))
            using (var stream2 = new FileStream(filePath2, FileMode.Open, FileAccess.Read))
            {
                int bytesRead1,
                    bytesRead2;
                do
                {
                    bytesRead1 = stream1.Read(buffer1, 0, bufferSize);
                    bytesRead2 = stream2.Read(buffer2, 0, bufferSize);

                    if (bytesRead1 != bytesRead2)
                        return false;

                    for (int i = 0; i < bytesRead1; i++)
                    {
                        if (buffer1[i] != buffer2[i])
                            return false;
                    }
                } while (bytesRead1 > 0);
            }

            return true;
        }

        public static bool ArraysAreEqual(byte[] first, byte[] second)
        {
            if (first == second)
                return true;
            if (first == null || second == null)
                return false;

            if (first.Length != second.Length)
                return false;

            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                    return false;
            }

            return true;
        }

        public static void testEverything(byte[]? arrayToCipher, String? fileToCipher)
        {
            CipheringMode[] cipheringModes = new CipheringMode[7]
            {
                CipheringMode.CBC,
                CipheringMode.CFB,
                CipheringMode.CTR,
                CipheringMode.ECB,
                CipheringMode.OFB,
                CipheringMode.PCBC,
                CipheringMode.RandomDelta,
            };

            PaddingMode[] paddingModes = new PaddingMode[4]
            {
                PaddingMode.Zeros,
                PaddingMode.ANSI_X923,
                PaddingMode.PKCS7,
                PaddingMode.ISO10126,
            };

            ICipheringAlgorithm[] cipheringAlgorithms = new ICipheringAlgorithm[3]
            {
                /* new DES(BitConverter.GetBytes(213213213123123)), //DES */
                new DEAL( //DEAL с 128 битовым ключом
                    BitConverter
                        .GetBytes(2131231312321231)
                        .Concat(BitConverter.GetBytes(1323213123123132132))
                        .ToArray()
                ),
                new DEAL( //DEAL с 192 битовым ключом
                    BitConverter
                        .GetBytes(2131231312321231)
                        .Concat(BitConverter.GetBytes(1323213123123132132))
                        .ToArray()
                        .Concat(BitConverter.GetBytes(12321312321312323))
                        .ToArray()
                ),
                new DEAL( //DEAL с 256 битовым ключом
                    BitConverter
                        .GetBytes(2131231312321231)
                        .Concat(BitConverter.GetBytes(1323213123123132132))
                        .ToArray()
                        .Concat(BitConverter.GetBytes(12321312321312323))
                        .ToArray()
                        .Concat(BitConverter.GetBytes(12321312312312331))
                        .ToArray()
                ),
            };

            for (int i = 0; i < cipheringAlgorithms.Length; i++)
            {
                for (int j = 0; j < cipheringModes.Length; j++)
                {
                    for (int k = 0; k < paddingModes.Length; k++)
                    {
                        Ciphering ciphrator = new Ciphering(
                            cipheringAlgorithms[i],
                            cipheringModes[j],
                            paddingModes[k]
                        );
                        if (fileToCipher != null)
                        { //Проверка шифрования массивов
                            String cipheredFilePath = makeChangedFilePath(
                                fileToCipher,
                                cipheringAlgorithms[i].ToString()
                                    + cipheringModes[j].ToString()
                                    + paddingModes[k].ToString()
                            );
                            String decipheredFilePath = makeChangedFilePath(
                                fileToCipher,
                                cipheringAlgorithms[i].ToString()
                                    + cipheringModes[j].ToString()
                                    + paddingModes[k].ToString()
                                    + new String("Decip")
                            );
                            try
                            {
                                ciphrator.cipherFile(fileToCipher, cipheredFilePath);
                                ciphrator.decipherFile(cipheredFilePath, decipheredFilePath);
                            }
                            catch (Exception ex)
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine(
                                    $"{cipheringAlgorithms[i].ToString()} {cipheringModes[j].ToString()} {paddingModes[k]} file ciphering failed with error: {ex.Message}"
                                );
                                Console.ForegroundColor = ConsoleColor.White;
                            }

                            if (filesAreEqual(fileToCipher, decipheredFilePath))
                            {
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine(
                                    $"{cipheringAlgorithms[i].ToString()} {cipheringModes[j].ToString()} {paddingModes[k]} ciphration is correct"
                                );
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(
                                    $"{cipheringAlgorithms[i].ToString()} {cipheringModes[j].ToString()} {paddingModes[k]} ciphration is not correct"
                                );
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                        }
                        if (arrayToCipher != null)
                        {
                            try
                            {
                                byte[] cipheredArray = new byte[arrayToCipher.Length];
                                ciphrator.cipherArray(arrayToCipher, ref cipheredArray);

                                byte[] decipheredArray = new byte[arrayToCipher.Length];
                                ciphrator.decipherArray(in cipheredArray, ref decipheredArray);

                                if (ArraysAreEqual(arrayToCipher, decipheredArray))
                                {
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.WriteLine(
                                        $"{cipheringAlgorithms[i].ToString()} {cipheringModes[j].ToString()} {paddingModes[k]} array ciphering is correct"
                                    );
                                    Console.ForegroundColor = ConsoleColor.White;
                                }
                                else
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine(
                                        $"{cipheringAlgorithms[i].ToString()} {cipheringModes[j].ToString()} {paddingModes[k]} array ciphering is not correct"
                                    );
                                    Console.ForegroundColor = ConsoleColor.White;

                                    Console.WriteLine($"  Original length: {arrayToCipher.Length}");
                                    Console.WriteLine(
                                        $"  Deciphered length: {decipheredArray.Length}"
                                    );
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine(
                                    $"{cipheringAlgorithms[i].ToString()} {cipheringModes[j].ToString()} {paddingModes[k]} array ciphering failed with error: {ex.Message}"
                                );
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                        }
                    }
                }
            }
        }

        static async Task CompareAsyncVsSync(string filePath)
        {
            var ciphrator = new Ciphering(
                new DEAL(
                    BitConverter
                        .GetBytes(2131231312321231)
                        .Concat(BitConverter.GetBytes(1323213123123132132))
                        .ToArray()
                ),
                CipheringMode.ECB,
                PaddingMode.PKCS7
            );

            var sw = Stopwatch.StartNew();
            await ciphrator.cipherFileAsync(filePath);
            await ciphrator.decipherFileAsync(makeChangedFilePath(filePath, "Cip"));
            sw.Stop();
            Console.WriteLine($"Async: {sw.ElapsedMilliseconds} ms");

            sw.Restart();
            ciphrator.cipherFile(filePath);
            ciphrator.decipherFile(makeChangedFilePath(filePath, "Cip"));
            sw.Stop();
            Console.WriteLine($"Sync: {sw.ElapsedMilliseconds} ms");
        }

        static async Task Main(String[] args)
        {
            /* Ciphering ciphrator = new Ciphering(
                new DEAL(
                    BitConverter
                        .GetBytes(2131231312321231)
                        .Concat(BitConverter.GetBytes(1323213123123132132))
                        .ToArray()
                ),
                CipheringMode.CBC,
                PaddingMode.PKCS7
            );
            ciphrator.cipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/BigInt.hpp");
            ciphrator.decipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/BigIntCip.hpp");
            Console.WriteLine(
                filesAreEqual(
                    "/home/gaalex/MAI/5sem/Сryptography/Lab1/First/BigInt.hpp",
                    "/home/gaalex/MAI/5sem/Сryptography/Lab1/First/BigIntCipDecip.hpp"
                )
            ); */

            //await CompareAsyncVsSync("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/test.png");
            Ciphering ciphrator = new Ciphering(
                new Rijndael(
                    BitConverter
                        .GetBytes(2131231312321231)
                        .Concat(BitConverter.GetBytes(1323213123123132132))
                        .ToArray()
                ),
                CipheringMode.CBC,
                PaddingMode.PKCS7
            );

            ciphrator.cipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/BigInt.hpp");
            ciphrator.decipherFile("/home/gaalex/MAI/5sem/Сryptography/Lab1/First/BigIntCip.hpp");

            /* byte[] test = new byte[16]
            {
                0x12,
                0x13,
                0x14,
                0x15,
                0x16,
                0x0a,
                0x0b,
                0x0c,
                0x12,
                0x1d,
                0xc4,
                0x15,
                0x1f,
                0x0a,
                0x1b,
                0x1c,
            };
            testEverything(test, null); */
        }
    }
}
