using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using KartLibrary.Encrypt;
using KartLibrary.IO;
using System.Diagnostics;
using System.IO.Compression;

namespace KartLibrary.File
{
    public class RhoDataInfo : IComparable<RhoDataInfo>
    {
        public uint Index { get; set; }
        public long Offset { get; set; }
        public int DataSize { get; set; }
        public int UncompressedSize { get; set; }
        public RhoBlockProperty BlockProperty { get; set; }
        public uint Checksum { get; set; }

        public int CompareTo(RhoDataInfo? other)
        {
            return Index.CompareTo(other?.Index);
        }

        public override int GetHashCode()
        {
            return (int)Index;
        }
    }

    //Extension
    public static class RhoBlockReader
    {
        public static RhoDataInfo ReadBlockInfo(this BinaryReader reader, uint Key)
        {
            RhoDataInfo output = new RhoDataInfo();
            byte[] blockInfoData = reader.ReadBytes(0x20);
            //Debug.Print($"adler_raw: {Adler.Adler32(0, blockInfoData, 0, blockInfoData.Length):x8}");
            blockInfoData = RhoEncrypt.DecryptHeaderInfo(blockInfoData, Key);
            uint hash = Adler.Adler32(0, blockInfoData, 0, blockInfoData.Length);

            using (MemoryStream ms = new MemoryStream(blockInfoData))
            {
                BinaryReader msReader = new BinaryReader(ms);
                output.Index = msReader.ReadUInt32();
                output.Offset = msReader.ReadUInt32() << 8;
                output.DataSize = msReader.ReadInt32();
                output.UncompressedSize = msReader.ReadInt32();
                output.BlockProperty = (RhoBlockProperty)msReader.ReadInt32();
                output.Checksum = msReader.ReadUInt32();
            }

            return output;
        }

        // For Rho layer 1.0
        public static RhoDataInfo ReadBlockInfo10(this BinaryReader reader, byte[] Key)
        {
            RhoDataInfo output = new RhoDataInfo();
            byte[] blockInfoData = reader.ReadBytes(0x20);
            blockInfoData = RhoEncrypt.DecryptBlockInfoOld(blockInfoData, Key);
            using (MemoryStream ms = new MemoryStream(blockInfoData))
            {
                BinaryReader msReader = new BinaryReader(ms);
                output.Index = msReader.ReadUInt32();
                output.Offset = msReader.ReadUInt32() << 8;
                output.DataSize = msReader.ReadInt32();
                output.UncompressedSize = msReader.ReadInt32();
                output.BlockProperty = (RhoBlockProperty)msReader.ReadInt32();
                output.Checksum = msReader.ReadUInt32();
            }

            return output;
        }

        public static byte[] ReadBlock(this BinaryReader reader, Rho rhoFile, uint blockIndex, uint key)
        {
            RhoDataInfo blockInfo = rhoFile.GetBlockInfo(blockIndex);

            reader.BaseStream.Seek(blockInfo.Offset, SeekOrigin.Begin);
            byte[] blockData = reader.ReadBytes(blockInfo.DataSize);
            //Debug.Print($"B:{BlockIndex:x8}: {Adler.Adler32(0, BlockData, 0, BlockData.Length):x8}");

            //EverPlanet不使用ZLib和任何壓縮方式
/*            if ((blockInfo.BlockProperty & RhoBlockProperty.Compressed) == RhoBlockProperty.Compressed)
            {
                using (MemoryStream ms = new MemoryStream(blockData))
                {
                    blockData = new byte[blockInfo.UncompressedSize];
                    Ionic.Zlib.ZlibStream ds = new Ionic.Zlib.ZlibStream(ms, Ionic.Zlib.CompressionMode.Decompress);
                    ds.Read(blockData, 0, blockData.Length);
                }
            }*/

            if ((blockInfo.BlockProperty & RhoBlockProperty.PartialEncrypted) ==
                RhoBlockProperty.PartialEncrypted) // Encrypted or PartialEncrypted
            {
                RhoEncrypt.DecryptData(key, blockData, 0, blockData.Length);
            }

            //PNG用 但有些檔案會出錯 pk_034e80ec.chi/TileRegionHigh.png
            if (blockInfo.BlockProperty == RhoBlockProperty.PartialEncrypted) // PartialEncrypted
            {
                RhoDataInfo secPartInfo = rhoFile.GetBlockInfo(blockIndex + 1);
                if (secPartInfo != null)
                {
                    Array.Resize(ref blockData, blockInfo.DataSize + secPartInfo.DataSize);
                    reader.BaseStream.ReadExactly(blockData, blockInfo.DataSize, secPartInfo.DataSize);
                }
            }

            //Debug.Print($"A:{BlockIndex:x8}: {Adler.Adler32(0, BlockData, 0, BlockData.Length):x8}");

            return blockData;
        }
    }

    public enum RhoBlockProperty
    {
        None,
        Compressed = 2,
        PartialEncrypted = 4,
        FullEncrypted = 5,
        CompressedEncrypted = FullEncrypted | Compressed
    }
}