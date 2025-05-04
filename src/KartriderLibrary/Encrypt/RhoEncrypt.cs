using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace KartLibrary.Encrypt
{
    public static class RhoEncrypt
    {
        /// <summary>
        /// Used to decrypt rho file data, or DataProcessed data.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] DecryptData(uint key, byte[] data)
        {
            byte[] extendedKey = RhoKey.ExtendKey(key);
            byte[] output = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                output[i] = (byte)(data[i] ^ extendedKey[i & 63]);
            }

            return output;
        }

        public static void DecryptData(uint key, byte[] data, int offset, int length)
        {
            if (offset + length > data.Length)
                throw new Exception("Over range.");

            byte[] extendedKey = RhoKey.ExtendKey(key);
            for (int i = 0; i < length; i++)
            {
                int index = i + offset;
                data[index] = (byte)(data[index] ^ extendedKey[index & 63]);
            }
        }

        /// <summary>
        /// Used to decrypt rho header, and block info.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static unsafe byte[] DecryptHeaderInfo(byte[] data, uint key)
        {
            uint currentKey = key;
            uint a = 0;
            byte[] output = new byte[data.Length];
            fixed (byte* wPtr = output, rPtr = data)
            {
                uint* writePtr = (uint*)wPtr;
                uint* readPtr = (uint*)rPtr;
                for (int i = 0; i < data.Length >> 2; i++)
                {
                    uint vector = RhoKey.GetVector(currentKey);
                    uint curData = readPtr[i];
                    curData ^= vector;
                    curData ^= a;
                    writePtr[i] = curData;
                    a += curData;
                    currentKey++;
                }
            }

            return output;
        }

        public static byte[] DecryptBlockInfoOld(byte[] Data, byte[] key)
        {
            if (Data.Length != 0x20)
                throw new NotSupportedException("Exception: the length of Data is not 32 bytes.");

            byte[] output = new byte[32];
            for (int i = 0; i < 32; i++)
                output[i] = (byte)(key[i] ^ Data[i]);

            return output;
        }

        /// <summary>
        /// Used to encrypt rho file data, or DataProcessed data.
        /// </summary>
        /// <param name="Data"></param>
        /// <param name="Key"></param>
        /// <returns></returns>
        public static byte[] EncryptData(uint Key, byte[] Data)
        {
            byte[] extendedKey = RhoKey.ExtendKey(Key);
            byte[] output = new byte[Data.Length];
            for (int i = 0; i < Data.Length; i++)
            {
                output[i] = (byte)(Data[i] ^ extendedKey[i & 63]);
            }

            return output;
        }

        public static void EncryptData(uint Key, byte[] Data, int Offset, int Length)
        {
            if (Offset + Length > Data.Length)
                throw new Exception("Over range.");
            byte[] extendedKey = RhoKey.ExtendKey(Key);
            for (int i = 0; i < Length; i++)
            {
                int index = i + Offset;
                Data[index] = (byte)(Data[index] ^ extendedKey[index & 63]);
            }
        }

        /// <summary>
        /// Used to encrypt rho header, and block info.
        /// </summary>
        /// <param name="Data"></param>
        /// <param name="Key"></param>
        /// <returns></returns>
        public static unsafe byte[] EncryptHeaderInfo(byte[] Data, uint Key)
        {
            uint currentKey = Key;
            uint a = 0;
            byte[] output = new byte[Data.Length];
            fixed (byte* wPtr = output, rPtr = Data)
            {
                uint* writePtr = (uint*)wPtr;
                uint* readPtr = (uint*)rPtr;
                for (int i = 0; i < Data.Length >> 2; i++)
                {
                    uint vector = RhoKey.GetVector(currentKey);
                    uint decData = readPtr[i];
                    uint encData = readPtr[i];
                    encData ^= vector;
                    encData ^= a;
                    writePtr[i] = encData;
                    a += decData;
                    currentKey++;
                }
            }

            return output;
        }

        public static byte[] EncryptBlockInfoOld(byte[] Data, byte[] key)
        {
            if (Data.Length != 0x20)
                throw new NotSupportedException("Exception: the length of Data is not 32 bytes.");
            byte[] output = new byte[32];
            for (int i = 0; i < 32; i++)
                output[i] = (byte)(key[i] ^ Data[i]);
            return output;
        }
    }
}