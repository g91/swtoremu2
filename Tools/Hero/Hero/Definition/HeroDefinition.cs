using ICSharpCode.SharpZipLib.Zip.Compression;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Hero.Definition
{
  public class HeroDefinition
  {
    protected byte[] Data;
    public string Name;
    protected int version;
    public HeroDefinition.Types Type;
    public int DomType;
    public string Description;
    public ulong Id;

    public bool IsCompressed
    {
      get
      {
        if (this.version == 1)
          return ((int) BitConverter.ToUInt16(this.Data, 4) & 1) != 0;
        if (this.version == 2)
          return ((int) BitConverter.ToUInt16(this.Data, 16) & 1) != 0;
        else
          throw new InvalidDataException("Invalid version");
      }
      set
      {
        if (this.version == 1)
        {
          this.Data[4] = (byte) ((int) this.Data[4] & 254 | (value ? 1 : 0));
        }
        else
        {
          if (this.version != 2)
            throw new InvalidDataException("Invalid version");
          this.Data[16] = (byte) ((int) this.Data[16] & 254 | (value ? 1 : 0));
        }
      }
    }

    protected ushort CompressedOffset
    {
      get
      {
        if (this.version == 1)
          return BitConverter.ToUInt16(this.Data, 6);
        if (this.version == 2)
          return BitConverter.ToUInt16(this.Data, 18);
        else
          throw new InvalidDataException("Invalid version");
      }
    }

    protected HeroDefinition()
    {
    }

    protected HeroDefinition(byte[] data, int version)
    {
      this.Data = data;
      this.version = version;
      if (version == 1)
      {
        this.DomType = (int) BitConverter.ToUInt16(this.Data, 4) >> 1 & 3;
        this.Type = (HeroDefinition.Types) ((int) BitConverter.ToUInt16(this.Data, 4) >> 3 & 15);
        this.Name = this.GetString(BitConverter.ToUInt16(this.Data, 16));
        this.Description = this.GetString(BitConverter.ToUInt16(this.Data, 18));
        this.Id = BitConverter.ToUInt64(this.Data, 8);
      }
      else if (version == 2)
      {
        this.DomType = (int) BitConverter.ToUInt16(this.Data, 16) >> 1 & 3;
        this.Type = (HeroDefinition.Types) ((int) BitConverter.ToUInt16(this.Data, 16) >> 3 & 15);
        this.Name = this.GetString(BitConverter.ToUInt16(this.Data, 20));
        this.Description = this.GetString(BitConverter.ToUInt16(this.Data, 22));
        this.Id = BitConverter.ToUInt64(this.Data, 8);
      }
      switch (this.Type)
      {
        case HeroDefinition.Types.Node:
          break;
        case HeroDefinition.Types.Enumeration:
          break;
        case HeroDefinition.Types.Field:
          break;
        case HeroDefinition.Types.Class:
          break;
        case HeroDefinition.Types.Association:
          break;
        case HeroDefinition.Types.Script:
          break;
        default:
          throw new InvalidDataException("definition type was unknown");
      }
    }

    protected string GetString(ushort offset)
    {
      ushort num = (ushort) 0;
      while ((int) this.Data[(int) offset + (int) num] != 0)
        ++num;
      return Encoding.ASCII.GetString(this.Data, (int) offset, (int) num);
    }

    public static HeroDefinition Create(byte[] data, int version)
    {
      HeroDefinition.Types types = (HeroDefinition.Types) 0;
      if (version == 1)
        types = (HeroDefinition.Types) ((int) BitConverter.ToUInt16(data, 4) >> 3 & 15);
      else if (version == 2)
        types = (HeroDefinition.Types) ((int) BitConverter.ToUInt16(data, 16) >> 3 & 15);
      switch (types)
      {
        case HeroDefinition.Types.Node:
          return (HeroDefinition) new HeroNodeDef(data, version);
        case HeroDefinition.Types.Enumeration:
          return (HeroDefinition) new HeroEnumDef(data, version);
        case HeroDefinition.Types.Field:
          return (HeroDefinition) new HeroFieldDef(data, version);
        case HeroDefinition.Types.Class:
          return (HeroDefinition) new HeroClassDef(data, version);
        case HeroDefinition.Types.Association:
          return (HeroDefinition) new HeroAssociationDef(data, version);
        default:
          return (HeroDefinition) null;
      }
    }

    protected void Decompress()
    {
      byte[] buffer = this.Data;
      if (!this.IsCompressed)
        return;
      Inflater inflater = new Inflater();
      ushort compressedOffset = this.CompressedOffset;
      inflater.SetInput(buffer, (int) compressedOffset, buffer.Length - (int) compressedOffset);
      List<KeyValuePair<byte[], int>> list = new List<KeyValuePair<byte[], int>>();
      int num1 = 0;
      int num2;
      do
      {
        byte[] numArray = new byte[163840];
        num2 = inflater.Inflate(numArray);
        list.Add(new KeyValuePair<byte[], int>(numArray, num2));
        num1 += num2;
      }
      while (num2 != 0);
      this.Data = new byte[num1 + (int) compressedOffset];
      Array.Copy((Array) buffer, 0, (Array) this.Data, 0, (int) compressedOffset);
      int destinationIndex = (int) compressedOffset;
      foreach (KeyValuePair<byte[], int> keyValuePair in list)
      {
        Array.Copy((Array) keyValuePair.Key, 0, (Array) this.Data, destinationIndex, keyValuePair.Value);
        destinationIndex += keyValuePair.Value;
      }
      this.IsCompressed = false;
      Array.Copy((Array) BitConverter.GetBytes(this.Data.Length), 0, (Array) this.Data, 0, 4);
    }

    public enum Types
    {
      Node = 1,
      Enumeration = 2,
      Field = 3,
      Class = 4,
      Association = 5,
      Script = 7,
    }
  }
}
