using System;
using System.IO;

namespace Hero
{
  public class DeserializeList : SerializeStateBase
  {
    public HeroTypes listType;
    public uint index;
    public bool m_30;

    public DeserializeList(PackedStream_2 stream, int valueState)
      : base(stream, HeroTypes.List)
    {
      this.index = 0U;
      this.m_30 = false;
      if (stream.Flags[4])
      {
        if (this.Next == null)
          throw new InvalidDataException("Only a HeroClass can be the root container type");
        else
          throw new NotImplementedException();
      }
      else
      {
        if (valueState != 1)
          throw new InvalidDataException("Invalid value state");
        if (stream.Flags[0])
        {
          ulong num;
          stream.Read(out num);
          this.listType = (HeroTypes) num;
        }
        stream.Read(out this.m_0C, out this.Count);
        if (stream.Style != 8 && stream.Style != 10)
          return;
        this.m_30 = ((int) this.Count & 1) == 1;
        DeserializeList deserializeList = this;
        int num1 = (int) (deserializeList.Count >> 1);
        deserializeList.Count = (uint) num1;
      }
    }

    public void GetFieldIndex(out uint index, out bool b, out int variableId)
    {
      ++this.index;
      if (this.m_30)
      {
        ulong num;
        this.Stream.Read(out num);
        b = ((long) num & 1L) == 1L;
        index = (uint) (num >> 1);
      }
      else
      {
        b = false;
        if (this.Stream.Flags[2])
        {
          ulong num;
          this.Stream.Read(out num);
          index = (uint) num;
        }
        else
          index = this.index;
      }
      variableId = this.ReadVariableId();
    }
  }
}
