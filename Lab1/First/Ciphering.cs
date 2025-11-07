using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using CipheringKeys;

namespace MyCiphering
{
    public class Ciphering
    {
        private ICipheringAlgorithm cipheringAlgorithm;
        private IPaddingMode paddingMode;
        private ICipheringMode cipheringMode;
        private byte[] initializeVector;

        public Ciphering(
            ICipheringAlgorithm cipheringAlgorithm,
            CipheringMode cipheringMode,
            PaddingMode paddingMode,
            byte[]? initializeVector = null
        )
        {
            this.cipheringAlgorithm = cipheringAlgorithm;
            if (initializeVector == null)
            {
                this.initializeVector = new byte[cipheringAlgorithm.BlockSize];
                Array.Fill<byte>(this.initializeVector, 0);
            }
            else
            {
                if (initializeVector.Length != this.cipheringAlgorithm.BlockSize)
                {
                    this.initializeVector = new byte[cipheringAlgorithm.BlockSize];
                    int delta = initializeVector.Length - cipheringAlgorithm.BlockSize;

                    if (delta < 0)
                    {
                        Array.Copy(
                            initializeVector,
                            this.initializeVector,
                            initializeVector.Length
                        );
                        for (int i = initializeVector.Length; i < -delta; i++)
                        {
                            this.initializeVector[i] = 0;
                        }
                    }
                    else
                    {
                        Array.Copy(
                            initializeVector,
                            this.initializeVector,
                            this.cipheringAlgorithm.BlockSize
                        );
                    }
                }
                this.initializeVector = (byte[])initializeVector.Clone();
            }
            switch (paddingMode)
            {
                case PaddingMode.Zeros:
                    this.paddingMode = new ZeroesPaddingMode();
                    break;
                case PaddingMode.ANSI_X923:
                    this.paddingMode = new ANSI_X923PaddingMode();
                    break;
                case PaddingMode.PKCS7:
                    this.paddingMode = new PKCS7PaddingMode();
                    break;
                case PaddingMode.ISO10126:
                    this.paddingMode = new ISO10126PaddingMode();
                    break;
                default:
                    throw new Exception("Нет такого режима паддинга.");
            }

            switch (cipheringMode)
            {
                case CipheringMode.ECB:
                    this.cipheringMode = new ECBCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.CBC:
                    this.cipheringMode = new CBCCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.PCBC:
                    this.cipheringMode = new PCBCCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.CFB:
                    this.cipheringMode = new CFBCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.OFB:
                    this.cipheringMode = new OFBCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.CTR:
                    this.cipheringMode = new CTRCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                case CipheringMode.RandomDelta:
                    this.cipheringMode = new RandomDeltaCipheringMode(
                        this.cipheringAlgorithm,
                        this.paddingMode
                    );
                    break;
                default:
                    throw new Exception("Нет такого режима шифрования!");
            }
        }

        public byte[] cipherBlock(in byte[] bytes)
        {
            return cipheringMode.cipher(in bytes, in initializeVector, true);
        }

        public byte[] decipherBlock(in byte[] bytes)
        {
            return cipheringMode.decipher(in bytes, in initializeVector, true);
        }

        public void cipherArray(in byte[] bytes, ref byte[] result)
        {
            result = cipheringMode.cipher(bytes, initializeVector, true);
        }

        public void decipherArray(in byte[] bytes, ref byte[] result)
        {
            result = cipheringMode.decipher(bytes, initializeVector, true);
        }

        private String makeChangedFilePath(String path, String toAdd)
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

        public bool cipherFile(String pathToFile)
        {
            String newPath;
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }
            else
            {
                newPath = makeChangedFilePath(pathToFile, "Cip");
                byte[] buffer = new byte[4096];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                using (FileStream fsW = new FileStream(newPath, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                            byte[] finalBlock = new byte[bytesRead];
                            Array.Copy(buffer, finalBlock, bytesRead);
                            cipheredBlockSizeBuffer = cipheringMode.cipher(
                                finalBlock,
                                this.initializeVector,
                                isFinalBlock
                            );
                            fsW.Write(cipheredBlockSizeBuffer);
                            break;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.cipher(
                            buffer,
                            this.initializeVector,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                    }
                }
            }
            return true;
        }

        public bool decipherFile(String pathToFile)
        {
            String newPath;
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }
            else
            {
                newPath = makeChangedFilePath(pathToFile, "Decip");
                byte[] buffer = new byte[4096];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                using (FileStream fsW = new FileStream(newPath, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                            byte[] finalBlock = new byte[bytesRead];
                            Array.Copy(buffer, finalBlock, bytesRead);
                            cipheredBlockSizeBuffer = cipheringMode.decipher(
                                finalBlock,
                                this.initializeVector,
                                isFinalBlock
                            );
                            fsW.Write(cipheredBlockSizeBuffer);
                            break;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.decipher(
                            buffer,
                            this.initializeVector,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                    }
                }
            }
            return true;
        }

        public bool cipherFile(String pathToFile, String outputFile)
        {
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }
            else
            {
                byte[] buffer = new byte[4096];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                using (FileStream fsW = new FileStream(outputFile, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                            byte[] finalBlock = new byte[bytesRead];
                            Array.Copy(buffer, finalBlock, bytesRead);
                            cipheredBlockSizeBuffer = cipheringMode.cipher(
                                finalBlock,
                                this.initializeVector,
                                isFinalBlock
                            );
                            fsW.Write(cipheredBlockSizeBuffer);
                            break;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.cipher(
                            buffer,
                            this.initializeVector,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                    }
                }
            }
            return true;
        }

        public bool decipherFile(String pathToFile, String outputFile)
        {
            if (!File.Exists(pathToFile))
            {
                Console.WriteLine("There's no such file");
                return false;
            }
            else
            {
                byte[] buffer = new byte[4096];
                byte[] cipheredBlockSizeBuffer;
                bool isFinalBlock = false;
                using (FileStream fsW = new FileStream(outputFile, FileMode.OpenOrCreate))
                using (FileStream fs = new FileStream(pathToFile, FileMode.Open))
                {
                    int bytesRead = 0;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (fs.Position == fs.Length)
                        {
                            isFinalBlock = true;
                            byte[] finalBlock = new byte[bytesRead];
                            Array.Copy(buffer, finalBlock, bytesRead);
                            cipheredBlockSizeBuffer = cipheringMode.decipher(
                                finalBlock,
                                this.initializeVector,
                                isFinalBlock
                            );
                            fsW.Write(cipheredBlockSizeBuffer);
                            break;
                        }
                        cipheredBlockSizeBuffer = cipheringMode.decipher(
                            buffer,
                            this.initializeVector,
                            isFinalBlock
                        );
                        fsW.Write(cipheredBlockSizeBuffer);
                    }
                }
            }
            return true;
        }
    }
}
