using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using KartLibrary.Encrypt;
using KartLibrary.IO;
using System.Diagnostics;
using System.Globalization;
using KartLibrary.File;

namespace KartLibrary.File
{
    [Obsolete("Rho class is deprecated. Use RhoArchive instead.")]
    public class Rho : IDisposable
    {
        internal Stream baseStream;

        private (double, string)[] MagicString =
        {
            (1.0d, "Rh layer spec 1.0"),
            (1.1d, "Rh layer spec 1.1"),
            (1.2d, "Ch layer spec 1.2"), //for EverPlanet
        };

        private double Version { get; set; }
        public string FileName { get; private set; }

        private uint RhoFileKey = 0;

        private uint BlockWhiteningKey = 0;

        private Dictionary<uint, RhoDataInfo> Blocks;

        public RhoDirectory RootDirectory { get; set; }

        public Rho(string fileName)
        {
            if (!System.IO.File.Exists(fileName))
                throw new FileNotFoundException($"Exception: Could't find the file:{fileName}.", fileName);

            FileStream fileStream = new FileStream(fileName, FileMode.Open);

            baseStream = new BufferedStream(fileStream, 4096); //Default: 4 KiB

            FileName = fileName;
            BinaryReader reader = new BinaryReader(baseStream);
            FileInfo fileInfo = new FileInfo(fileName);

            // RhoFileKey = 0x93407EB1; //for pk_2D4AF218
            // RhoFileKey = 0x7C1B1939; //for pk_16258CA0
            // RhoFileKey = 0x7C1B1938; //for pk_16258C9F
            // RhoFileKey = 0xC12D80A1; //for pk_1B37F409

            // RhoFileKey = uint.Parse(fileInfo.Name.Replace("pk_", "").Replace(".chi", ""), NumberStyles.HexNumber) + 0x25F58C9A;
            // RhoFileKey = uint.Parse(fileInfo.Name.Replace("pk_", "").Replace(".chi", ""), NumberStyles.HexNumber) + 0x65F58C99;
            // RhoFileKey = uint.Parse(fileInfo.Name.Replace("pk_", "").Replace(".chi", ""), NumberStyles.HexNumber) + 0xA5F58C98;
            // RhoFileKey = uint.Parse(fileInfo.Name.Replace("pk_", "").Replace(".chi", ""), NumberStyles.HexNumber) + 0xE5F58C97;

            // RhoFileKey = RhoKey.GetRhoKey(fileInfo.Name.Replace(".rho", ""));

            // Read Magic String
            byte[] magicStrBytes = reader.ReadBytes(0x22);
            string magicStr = Encoding.GetEncoding("UTF-16").GetString(magicStrBytes);
            int verIndex = Array.FindIndex(MagicString, x => x.Item2 == magicStr);
            if (verIndex == -1)
                throw new NotSupportedException("Exception: This file is not supported.");

            Version = MagicString[verIndex].Item1;

            baseStream.Seek(0x80, SeekOrigin.Begin); //跳過

            // Part 2
            byte[] part2Data = reader.ReadBytes(0x80);

            switch (Version)
            {
                case 1.0d:
                    RhoEncrypt.DecryptData(RhoFileKey, part2Data, 0, part2Data.Length);
                    break;
                case 1.1d:
                    part2Data = RhoEncrypt.DecryptHeaderInfo(part2Data, RhoFileKey);
                    break;
                case 1.2d:
                    var baseKey = uint.Parse(fileInfo.Name.Replace("pk_", "").Replace(".chi", ""),
                        NumberStyles.HexNumber);
                    uint[] keyOffsets =
                    {
                        0x25F58C9A,
                        0x65F58C99,
                        0xA5F58C98,
                        0xE5F58C97
                    };
                    foreach (uint key in keyOffsets)
                    {
                        RhoFileKey = baseKey + key;

                        byte[] temp = RhoEncrypt.DecryptHeaderInfo(part2Data, RhoFileKey);
                        int magicCode = BitConverter.ToInt32(temp, 4);
                        if (magicCode == 0x10002)
                        {
                            part2Data = temp;
                            break;
                        }
                    }

                    break;
            }

            int blockCount;
            byte[] blockInfoKeyOld = new byte[0]; // For 1.0 version
            uint blockInfoKey; // For 1.1 version

            using (MemoryStream ms = new MemoryStream(part2Data))
            {
                BinaryReader br = new BinaryReader(ms);
                uint part2Hash = br.ReadUInt32();
                uint checkHash = Adler.Adler32(0, part2Data, 4, 0x7C);
                // if (part2Hash != checkHash)
                // throw new NotSupportedException("Exception: This file was modified. [ Part 2 Hash not euqal ]");

                int magicCode = br.ReadInt32();

                if (Version == 1.0d && magicCode != 0x10000 ||
                    Version == 1.1d && magicCode != 0x10001 ||
                    Version == 1.2d && magicCode != 0x10002)
                    throw new NotSupportedException("Exception: This file is not Rho File. [ Header check failure ]");

                blockCount = br.ReadInt32(); // 10
                BlockWhiteningKey = br.ReadUInt32(); //14 // BlockInfoKey = RhoFileKey ^  BlockWhiteningKey. 
                blockInfoKey = RhoFileKey ^ BlockWhiteningKey;

                switch (Version)
                {
                    case 1.0d:
                        blockInfoKeyOld = br.ReadBytes(32);
                        break;
                    case 1.1d:
                    case 1.2d:
                    {
                        int u1a = br.ReadInt32(); //=1
                        int u2a = br.ReadInt32(); //=RhoKey - 397E40C3
                        br.ReadInt32(); // in aaa.pk file
                        //Debug.Print($"DataHash: {DataHash:x8}");
                        break;
                    }
                }

                int endMagicCode = br.ReadInt32(); // = FC1F9778

                Blocks = new Dictionary<uint, RhoDataInfo>(blockCount);
            }

            baseStream.Seek(0x100, SeekOrigin.Begin);
            // Part 3
            for (int i = 0; i < blockCount; i++)
            {
                switch (Version)
                {
                    case 1.0d:
                    {
                        var blockInfo = reader.ReadBlockInfo10(blockInfoKeyOld);
                        Blocks.Add(blockInfo.Index, blockInfo);
                        break;
                    }
                    case 1.1d:
                    case 1.2d:
                    {
                        var blockInfo = reader.ReadBlockInfo(blockInfoKey);
                        Blocks.Add(blockInfo.Index, blockInfo);
                        blockInfoKey++;
                        break;
                    }
                }
            }

            // Part 4
            RootDirectory = new RhoDirectory(this);
            RootDirectory.DirectoryName = "";
            RootDirectory.DirIndex = 0xFFFFFFFF;
            Queue<RhoDirectory> processQueue = new Queue<RhoDirectory>();
            processQueue.Enqueue(RootDirectory);
            while (processQueue.Count > 0)
            {
                RhoDirectory curDir = processQueue.Dequeue();
                byte[] dirData = reader.ReadBlock(this, curDir.DirIndex, RhoKey.GetDirectoryDataKey(RhoFileKey));

                curDir.GetFromDirInfo(dirData);
                foreach (RhoDirectory subdir in curDir.GetDirectories())
                {
                    processQueue.Enqueue(subdir);
                }
            }

            List<RhoDataInfo> trtt = new List<RhoDataInfo>();
            foreach (var blockKeyPair in Blocks)
            {
                trtt.Add(blockKeyPair.Value);
            }
        }

        internal uint GetFileKey()
        {
            return RhoFileKey;
        }

        internal RhoDataInfo GetBlockInfo(uint Index)
        {
            if (!Blocks.TryGetValue(Index, out var info))
                return null;
            return info;
        }

        internal byte[] GetBlockData(uint BlockIndex, uint Key)
        {
            BinaryReader reader = new BinaryReader(baseStream);
            byte[] output = reader.ReadBlock(this, BlockIndex, Key);
            uint adler = Adler.Adler32(0, output, 0, output.Length);
            return output;
        }

        public RhoFileInfo GetFile(string Path)
        {
            string[] PathSplit = Path.Split('/');
            RhoDirectory rd = RootDirectory;
            for (int i = 1; i < PathSplit.Length - 1; i++)
            {
                string curPathName = PathSplit[i].Trim();
                if (curPathName == "")
                    continue;
                RhoDirectory nextDir = rd.GetDirectory(curPathName);
                if (nextDir is null)
                    return null;
                rd = nextDir;
            }

            return rd.GetFile(PathSplit[PathSplit.Length - 1]);
        }

        public void Dispose()
        {
            baseStream.Close();
            baseStream.Dispose();
            Blocks = null;
        }

        ~Rho()
        {
            Dispose();
        }
    }
}