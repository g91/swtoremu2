using System;

namespace Hero
{
  public class SerializeList : SerializeStateBase
  {
    public HeroTypes listType;
    public int index;

    public SerializeList(PackedStream_2 stream, int valueState, HeroTypes listType, int Count)
      : base(stream, HeroTypes.List)
    {
      this.index = 0;
      if (stream.Flags[4])
        throw new NotImplementedException();
      if (stream.Flags[0])
      {
        ulong num = (ulong) listType;
        stream.Write(num);
      }
      if (stream.Style == 8 || stream.Style == 10)
        stream.Write(Count * 2, Count * 2);
      else
        stream.Write(Count, Count);
    }

    public void SetFieldIndex(int index, int variableId)
    {
      ++this.index;
      if (this.Stream.Flags[2])
      {
        this.Stream.Write((ulong) index);
        this.index = index;
      }
      else if (this.index != index)
        throw new SerializingException("Wrong index");
      this.WriteVariableId(variableId);
    }
  }
}
