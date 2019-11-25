using Hero;

namespace Hero.Types
{
  public class HeroGuid : HeroAnyValue
  {
    public ulong GUID;

    public override string ValueText
    {
      get
      {
        return string.Format("{0:X8}", (object) this.GUID);
      }
    }

    public HeroGuid(ulong GUID = 0UL)
    {
      this.Type = new HeroType(HeroTypes.Guid);
      this.hasValue = true;
      this.GUID = GUID;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      stream.Read(out this.GUID);
    }

    public override void Serialize(PackedStream_2 stream)
    {
      stream.Write(this.GUID);
    }
  }
}
