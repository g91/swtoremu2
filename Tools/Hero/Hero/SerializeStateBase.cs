namespace Hero
{
  public class SerializeStateBase
  {
    protected SerializeStateBase Next;
    public PackedStream_2 Stream;
    public HeroTypes HeroType;
    protected uint m_0C;
    public uint Count;

    public SerializeStateBase(PackedStream_2 stream, HeroTypes heroType)
    {
      this.HeroType = heroType;
      this.Next = (SerializeStateBase) null;
      this.Stream = stream;
      this.m_0C = 0U;
      this.Count = 0U;
      this.Next = stream.State;
      stream.State = this;
    }

    public int ReadVariableId()
    {
      if (!this.Stream.Flags[1] || (int) this.Stream.TransportVersion >= 5)
        return 0;
      ulong num;
      this.Stream.Read(out num);
      return (int) num;
    }

    public void WriteVariableId(int variableId)
    {
      if (!this.Stream.Flags[1])
        return;
      this.Stream.Write((ulong) variableId);
    }
  }
}
