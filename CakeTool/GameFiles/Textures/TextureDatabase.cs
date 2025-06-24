using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using CakeTool.Hashing;

using Syroot.BinaryData;

namespace CakeTool.GameFiles.Textures;

public class TextureDatabase
{
    // v5 = 24
    // v6 = 25
    public uint Version { get; set; }

    public SortedDictionary<ulong, TextureMeta> TextureInfos { get; set; } = [];

    /// <summary>
    /// 'T_DB'
    /// </summary>
    public static readonly uint MAGIC = BinaryPrimitives.ReadUInt32LittleEndian("T_DB"u8);

    public TextureDatabase(byte version = 6)
    {
        Version = version;
    }

    public TextureMeta Add(string path, TextureMeta textureMeta)
    {
        ulong hash = FNV1A64.FNV64StringI(path.Replace('\\', '/'));
        textureMeta.FilePathHash = hash;

        if (!TextureInfos.ContainsKey(hash))
            TextureInfos.Add(hash, textureMeta);
        else
            TextureInfos[hash] = textureMeta;

        return textureMeta;
    }

    public void Read(Stream stream)
    {
        var bs = new BinaryStream(stream, ByteConverter.Little);
        uint magic = bs.ReadUInt32();
        if (magic != MAGIC && 
            magic != 0x4244545F) // _TDB (not sure which tool generates _TDB..? that doesn't even seem valid)
            throw new InvalidDataException("Could not read texture database - file is not a texture database.");

        Version = bs.ReadUInt32();
        uint numTextureInfos = bs.ReadUInt32();
        uint structSize = bs.ReadUInt32();

        long basePos = bs.BaseStream.Position;
        for (int i = 0; i < numTextureInfos; i++)
        {
            bs.Position = basePos + i * structSize;
            
            ulong hash = bs.ReadUInt64();

            var textureInfo = new TextureMeta();
            textureInfo.Read(bs);
            TextureInfos.Add(hash, textureInfo);
        }
    }

    public static TextureDatabase Open(string fileName)
    {
        using var fs = File.OpenRead(fileName);

        var tdb = new TextureDatabase();
        tdb.Read(fs);
        return tdb;
    }

    public void Write(Stream stream)
    {
        var bs = new BinaryStream(stream);
        bs.WriteUInt32(MAGIC);
        bs.WriteUInt32(Version);
        bs.WriteUInt32((uint)TextureInfos.Count);

        uint structSize = Version switch
        {
            5 => TextureMeta.GetSize(13),
            6 => TextureMeta.GetSize(14),
        };
        bs.WriteUInt32(0x08 + structSize);

        foreach (KeyValuePair<ulong, TextureMeta> kv in TextureInfos)
        {
            bs.WriteUInt64(kv.Key);
            kv.Value.Write(bs);
        }
    }

    public bool TryGetTexture(string name, out TextureMeta textureInfo)
    {
        ulong hash = FNV1A64.FNV64StringI(name.Replace('\\', '/'));
        return TextureInfos.TryGetValue(hash, out textureInfo!);
    }
}