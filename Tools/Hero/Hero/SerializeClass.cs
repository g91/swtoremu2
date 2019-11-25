using System;
using System.IO;

namespace Hero
{
  public class SerializeClass : SerializeStateBase
  {
    public ulong m_28;
    public int m_30;
    public int m_34;
    public object m_38;

    public SerializeClass(PackedStream_2 stream, int valueState, int count)
      : base(stream, HeroTypes.Class)
    {
      this.m_28 = 0UL;
      this.m_30 = this.m_34 = 0;
      this.m_38 = (object) null;
      if (stream.Flags[4])
        throw new NotImplementedException();
      stream.Write(count, count);
    }

    public void WriteFieldData(ulong fieldId, HeroTypes type, int variableId)
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
          this.Stream.Write((long) fieldId - (long) this.m_28);
          this.m_28 = fieldId;
          if (this.Stream.Flags[0])
            this.Stream.Write((ulong) type);
          this.WriteVariableId(variableId);
          break;
      }
    }
  }
}
