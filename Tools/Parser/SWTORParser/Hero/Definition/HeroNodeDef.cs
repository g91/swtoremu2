using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SWTORParser.Hero.Types;

namespace SWTORParser.Hero.Definition
{
    public class HeroNodeDef : HeroDefinition
    {
        public ushort _14;
        public ushort _16;
        public ushort _2A;
        public byte _2D;
        public DefinitionId baseClass;
        public List<DefinitionId> glomClasses;
        public List<DefinitionId> glomClasses2;
        protected bool isProto;
        public byte[] serializedData;
        public byte streamStyle;
        protected VariableList variables;

        public HeroNodeDef(byte[] data, int version)
            : base(data, version)
        {
            ushort num1 = 0;
            ushort num2 = 0;
            ushort num3;
            ushort num4;
            if (version == 1)
            {
                _14 = BitConverter.ToUInt16(Data, 20);
                _16 = BitConverter.ToUInt16(Data, 22);
                baseClass = new DefinitionId(BitConverter.ToUInt64(Data, 24));
                num3 = BitConverter.ToUInt16(Data, 32);
                num4 = BitConverter.ToUInt16(Data, 34);
            }
            else
            {
                if (version != 2)
                    throw new InvalidDataException("Invalid version");
                baseClass = new DefinitionId(BitConverter.ToUInt64(Data, 24));
                _14 = BitConverter.ToUInt16(Data, 32);
                _16 = BitConverter.ToUInt16(Data, 34);
                num3 = BitConverter.ToUInt16(Data, 36);
                num4 = BitConverter.ToUInt16(Data, 38);
                num1 = BitConverter.ToUInt16(Data, 42);
                num2 = BitConverter.ToUInt16(Data, 44);
            }
            glomClasses = new List<DefinitionId>();
            for (ushort index = 0; (int) index < (int) num3; ++index)
                glomClasses.Add(new DefinitionId(BitConverter.ToUInt64(Data, num4 + 8*index)));
            glomClasses2 = new List<DefinitionId>();
            for (ushort index = 0; (int) index < (int) num1; ++index)
                glomClasses2.Add(new DefinitionId(BitConverter.ToUInt64(Data, num2 + 8*index)));
            isProto = false;
        }

        public HeroNodeDef(OmegaStream stream)
        {
            Type = Types.Node;
            stream.CheckResourceHeader(1414484560U, 2, 2);

            Id = stream.ReadULong();
            Name = stream.ReadString();
            Description = stream.ReadString();

            /*var num1 = (Int32)*/stream.ReadUInt();
            /*var num2 = (Int32)*/stream.ReadUInt();

            baseClass = new DefinitionId(stream.ReadULong());

            if (stream.TransportVersion < 5)
                /*var num3 = (Int32)*/stream.ReadUInt();

            glomClasses = new List<DefinitionId>();
            int num4 = stream.ReadInt();
            for (int index = 0; index < num4; ++index)
                glomClasses.Add(new DefinitionId(stream.ReadULong()));

            /*var num5 = (Int32)*/stream.ReadByte();
            /*var streamFormat = */stream.ReadUShort();

            if (stream.TransportVersion >= 3)
                streamStyle = stream.ReadByte();

            if (stream.TransportVersion < 4)
            {
                var co = stream.ReadUInt();
                for (var i = 0U; i < co; ++i)
                {
                    stream.ReadULong();
                    stream.ReadUInt();
                }
                var len = stream.ReadUInt();
                stream.ReadBytes(len);
                //throw new NotImplementedException();
            }
            else
            {
                var length = stream.ReadUInt();
                serializedData = stream.ReadBytes(length);
                isProto = true;
            }
        }

        public VariableList Variables
        {
            get
            {
                if (variables == null)
                    Serialize();

                return variables;
            }
        }

        public void Serialize()
        {
            variables = new VariableList();
            if (!isProto)
            {
                Decompress();
                int startIndex = version != 1 ? 40 : 36;
                uint num1 = BitConverter.ToUInt32(Data, startIndex);
                ushort num2 = BitConverter.ToUInt16(Data, startIndex + 4);
                serializedData = new byte[num1];
                Array.Copy(Data, num2, serializedData, 0L, num1);
                _2A = BitConverter.ToUInt16(Data, startIndex + 6);
                streamStyle = Data[startIndex + 8];
                _2D = (byte) (Data[startIndex + 9] & 3U);
            }
            if (serializedData.Length == 0)
                return;
            byte[] bytes = Encoding.ASCII.GetBytes("azalie");
            byte num = 0;
            for (int index = 0; index < serializedData.Length; ++index)
            {
                if (bytes[num] == serializedData[index] || bytes[num] == serializedData[index] + 97 - 65)
                {
                    ++num;
                    if (num == bytes.Length)
                    {
                        Console.WriteLine(Name);
                        break;
                    }
                }
                else
                    num = 0;
            }
            var stream = new PackedStream2(streamStyle, serializedData);
            var deserializeClass = new DeserializeClass(stream, 1);
            for (uint index = 0U; index < deserializeClass.Count; ++index)
            {
                uint type1 = 0U;
                int variableId = 0;
                ulong fieldId;
                int d;
                deserializeClass.ReadFieldData(out fieldId, ref type1, ref variableId, out d);
                if (d != 2)
                {
                    var type2 = new HeroType((HeroTypes) type1);
                    var field = new DefinitionId(fieldId);
                    if (field.Definition != null)
                        type2 = (field.Definition as HeroFieldDef).FieldType;
                    HeroAnyValue heroAnyValue = HeroAnyValue.Create(type2);
                    heroAnyValue.Deserialize(stream);
                    Variables.Add(new Variable(field, variableId, heroAnyValue));
                }
            }
        }

        public override string ToString()
        {
            return "Node " + Name;
        }
    }
}