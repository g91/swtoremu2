using Hero;
using Hero.Types;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Hero.Definition
{
  public class HeroNodeDef : HeroDefinition
  {
    public ushort _14;
    public ushort _16;
    public DefinitionId baseClass;
    public List<DefinitionId> glomClasses;
    public List<DefinitionId> glomClasses2;
    public byte[] serializedData;
    public ushort _2A;
    public byte streamStyle;
    public byte _2D;
    protected VariableList variables;
    protected bool isProto;

    public VariableList Variables
    {
      get
      {
        if (this.variables == null)
          this.Serialize();
        return this.variables;
      }
    }

    public HeroNodeDef(byte[] data, int version)
      : base(data, version)
    {
      ushort num1 = (ushort) 0;
      ushort num2 = (ushort) 0;
      ushort num3;
      ushort num4;
      if (version == 1)
      {
        this._14 = BitConverter.ToUInt16(this.Data, 20);
        this._16 = BitConverter.ToUInt16(this.Data, 22);
        this.baseClass = new DefinitionId(BitConverter.ToUInt64(this.Data, 24));
        num3 = BitConverter.ToUInt16(this.Data, 32);
        num4 = BitConverter.ToUInt16(this.Data, 34);
      }
      else
      {
        if (version != 2)
          throw new InvalidDataException("Invalid version");
        this.baseClass = new DefinitionId(BitConverter.ToUInt64(this.Data, 24));
        this._14 = BitConverter.ToUInt16(this.Data, 32);
        this._16 = BitConverter.ToUInt16(this.Data, 34);
        num3 = BitConverter.ToUInt16(this.Data, 36);
        num4 = BitConverter.ToUInt16(this.Data, 38);
        num1 = BitConverter.ToUInt16(this.Data, 42);
        num2 = BitConverter.ToUInt16(this.Data, 44);
      }
      this.glomClasses = new List<DefinitionId>();
      for (ushort index = (ushort) 0; (int) index < (int) num3; ++index)
        this.glomClasses.Add(new DefinitionId(BitConverter.ToUInt64(this.Data, (int) num4 + 8 * (int) index)));
      this.glomClasses2 = new List<DefinitionId>();
      for (ushort index = (ushort) 0; (int) index < (int) num1; ++index)
        this.glomClasses2.Add(new DefinitionId(BitConverter.ToUInt64(this.Data, (int) num2 + 8 * (int) index)));
      this.isProto = false;
    }

    public HeroNodeDef(OmegaStream stream)
    {
      this.Type = HeroDefinition.Types.Node;
      stream.CheckResourceHeader(1414484560U, (ushort) 2, (ushort) 2);
      this.Id = stream.ReadULong();
      this.Name = stream.ReadString();
      this.Description = stream.ReadString();
      int num1 = (int) stream.ReadUInt();
      int num2 = (int) stream.ReadUInt();
      this.baseClass = new DefinitionId(stream.ReadULong());
      if ((int) stream.TransportVersion < 5)
      {
        int num3 = (int) stream.ReadUInt();
      }
      this.glomClasses = new List<DefinitionId>();
      int num4 = stream.ReadInt();
      for (int index = 0; index < num4; ++index)
        this.glomClasses.Add(new DefinitionId(stream.ReadULong()));
      int num5 = (int) stream.ReadByte();
      if ((int) stream.ReadUShort() >= 3)
        this.streamStyle = stream.ReadByte();
      uint length = stream.ReadUInt();
      this.serializedData = stream.ReadBytes(length);
      this.isProto = true;
    }

    public void Serialize()
    {
      this.variables = new VariableList();
      if (!this.isProto)
      {
        this.Decompress();
        int startIndex = this.version != 1 ? 40 : 36;
        uint num1 = BitConverter.ToUInt32(this.Data, startIndex);
        ushort num2 = BitConverter.ToUInt16(this.Data, startIndex + 4);
        this.serializedData = new byte[num1];
        Array.Copy((Array) this.Data, (long) num2, (Array) this.serializedData, 0L, (long) num1);
        this._2A = BitConverter.ToUInt16(this.Data, startIndex + 6);
        this.streamStyle = this.Data[startIndex + 8];
        this._2D = (byte) ((uint) this.Data[startIndex + 9] & 3U);
      }
      if (this.serializedData.Length == 0)
        return;
      byte[] bytes = Encoding.ASCII.GetBytes("azalie");
      byte num = (byte) 0;
      for (int index = 0; index < this.serializedData.Length; ++index)
      {
        if ((int) bytes[(int) num] == (int) this.serializedData[index] || (int) bytes[(int) num] == (int) this.serializedData[index] + 97 - 65)
        {
          ++num;
          if ((int) num == bytes.Length)
          {
            Console.WriteLine(this.Name);
            break;
          }
        }
        else
          num = (byte) 0;
      }
      PackedStream_2 stream = new PackedStream_2((int) this.streamStyle, this.serializedData);
      DeserializeClass deserializeClass = new DeserializeClass(stream, 1);
      for (uint index = 0U; index < deserializeClass.Count; ++index)
      {
        uint type1 = 0U;
        int variableId = 0;
        ulong fieldId;
        int d;
        deserializeClass.ReadFieldData(out fieldId, ref type1, ref variableId, out d);
        if (d != 2)
        {
          HeroType type2 = new HeroType((HeroTypes) type1);
          DefinitionId field = new DefinitionId(fieldId);
          if (field.Definition != null)
            type2 = (field.Definition as HeroFieldDef).FieldType;
          HeroAnyValue heroAnyValue = HeroAnyValue.Create(type2);
          heroAnyValue.Deserialize(stream);
          this.Variables.Add(new Variable(field, variableId, heroAnyValue));
        }
      }
    }

    public override string ToString()
    {
      return "Node " + this.Name;
    }
  }
}
