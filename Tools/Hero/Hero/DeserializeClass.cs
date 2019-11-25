using System;
using System.IO;

namespace Hero
{
  public class DeserializeClass : SerializeStateBase
  {
    public ulong m_28;
    public int m_30;
    public int m_34;
    public object m_38;

    public DeserializeClass(PackedStream_2 stream, int valueState)
      : base(stream, HeroTypes.Class)
    {
      this.m_28 = 0UL;
      this.m_30 = this.m_34 = 0;
      this.m_38 = (object) null;
      if (stream.Flags[4])
      {
        if (valueState == 0)
          return;
        if (valueState != 1)
          throw new InvalidDataException("Invalid value state");
        if (this.Next != null)
          throw new NotImplementedException();
        ulong num;
        this.Stream.Read(out num);
        throw new NotImplementedException();
      }
      else
      {
        if (valueState != 1)
          throw new InvalidDataException("Invalid value state");
        stream.Read(out this.m_0C, out this.Count);
      }
    }

    public void ReadFieldData(out ulong fieldId, ref uint type, ref int variableId, out int d)
    {
      switch (this.Stream.Style)
      {
        case 7:
          throw new InvalidDataException("Unable to get field id");
        case 8:
          throw new InvalidDataException("Unable to get field id");
        case 9:
        case 10:
          throw new InvalidDataException("Unable to get field id");
        default:
          long num1;
          this.Stream.Read(out num1);
          fieldId = this.m_28 + (ulong) num1;
          if (this.Stream.Flags[0])
          {
            ulong num2;
            this.Stream.Read(out num2);
            type = (uint) num2;
          }
          variableId = this.ReadVariableId();
          d = 1;
          this.m_28 = fieldId;
          break;
      }
    }
  }
}
