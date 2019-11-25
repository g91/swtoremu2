using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ICSharpCode.SharpZipLib.Zip.Compression;

namespace SWTORParser.Hero.Definition
{
    public class HeroDefinition
    {
        #region Types enum

        public enum Types
        {
            Node = 1,
            Enumeration = 2,
            Field = 3,
            Class = 4,
            Association = 5,
            Script = 7,
        }

        #endregion

        protected byte[] Data;
        public string Description;
        public int DomType;
        public ulong Id;
        public string Name;
        public Types Type;
        protected int version;

        protected HeroDefinition()
        {
        }

        protected HeroDefinition(byte[] data, int version)
        {
            Data = data;
            this.version = version;
            if (version == 1)
            {
                DomType = BitConverter.ToUInt16(Data, 4) >> 1 & 3;
                Type = (Types) (BitConverter.ToUInt16(Data, 4) >> 3 & 15);
                Name = GetString(BitConverter.ToUInt16(Data, 16));
                Description = GetString(BitConverter.ToUInt16(Data, 18));
                Id = BitConverter.ToUInt64(Data, 8);
            }
            else if (version == 2)
            {
                DomType = BitConverter.ToUInt16(Data, 16) >> 1 & 3;
                Type = (Types) (BitConverter.ToUInt16(Data, 16) >> 3 & 15);
                Name = GetString(BitConverter.ToUInt16(Data, 20));
                Description = GetString(BitConverter.ToUInt16(Data, 22));
                Id = BitConverter.ToUInt64(Data, 8);
            }
            switch (Type)
            {
                case Types.Node:
                    break;
                case Types.Enumeration:
                    break;
                case Types.Field:
                    break;
                case Types.Class:
                    break;
                case Types.Association:
                    break;
                case Types.Script:
                    break;
                default:
                    throw new InvalidDataException("definition type was unknown");
            }
        }

        public bool IsCompressed
        {
            get
            {
                if (version == 1)
                    return (BitConverter.ToUInt16(Data, 4) & 1) != 0;
                if (version == 2)
                    return (BitConverter.ToUInt16(Data, 16) & 1) != 0;
                else
                    throw new InvalidDataException("Invalid version");
            }
            set
            {
                if (version == 1)
                {
                    Data[4] = (byte) (Data[4] & 254 | (value ? 1 : 0));
                }
                else
                {
                    if (version != 2)
                        throw new InvalidDataException("Invalid version");
                    Data[16] = (byte) (Data[16] & 254 | (value ? 1 : 0));
                }
            }
        }

        protected ushort CompressedOffset
        {
            get
            {
                if (version == 1)
                    return BitConverter.ToUInt16(Data, 6);
                if (version == 2)
                    return BitConverter.ToUInt16(Data, 18);
                else
                    throw new InvalidDataException("Invalid version");
            }
        }

        protected string GetString(ushort offset)
        {
            ushort num = 0;
            while (Data[offset + num] != 0)
                ++num;
            return Encoding.ASCII.GetString(Data, offset, num);
        }

        public static HeroDefinition Create(byte[] data, int version)
        {
            Types types = 0;
            if (version == 1)
                types = (Types) (BitConverter.ToUInt16(data, 4) >> 3 & 15);
            else if (version == 2)
                types = (Types) (BitConverter.ToUInt16(data, 16) >> 3 & 15);
            switch (types)
            {
                case Types.Node:
                    return new HeroNodeDef(data, version);

                case Types.Enumeration:
                    return new HeroEnumDef(data, version);

                case Types.Field:
                    return new HeroFieldDef(data, version);

                case Types.Class:
                    return new HeroClassDef(data, version);

                case Types.Association:
                    return new HeroAssociationDef(data, version);

                default:
                    return null;
            }
        }

        protected void Decompress()
        {
            byte[] buffer = Data;
            if (!IsCompressed)
                return;
            var inflater = new Inflater();
            ushort compressedOffset = CompressedOffset;
            inflater.SetInput(buffer, compressedOffset, buffer.Length - compressedOffset);
            var list = new List<KeyValuePair<byte[], int>>();
            int num1 = 0;
            int num2;
            do
            {
                var numArray = new byte[163840];
                num2 = inflater.Inflate(numArray);
                list.Add(new KeyValuePair<byte[], int>(numArray, num2));
                num1 += num2;
            } while (num2 != 0);
            Data = new byte[num1 + compressedOffset];
            Array.Copy(buffer, 0, Data, 0, compressedOffset);
            int destinationIndex = compressedOffset;
            foreach (var keyValuePair in list)
            {
                Array.Copy(keyValuePair.Key, 0, Data, destinationIndex, keyValuePair.Value);
                destinationIndex += keyValuePair.Value;
            }
            IsCompressed = false;
            Array.Copy(BitConverter.GetBytes(Data.Length), 0, Data, 0, 4);
        }
    }
}