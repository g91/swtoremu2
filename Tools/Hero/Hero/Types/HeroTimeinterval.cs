using Hero;

namespace Hero.Types
{
  public class HeroTimeinterval : HeroAnyValue
  {
    public long Value;

    public override string ValueText
    {
      get
      {
        return string.Format("{0}", (object) this.Value);
      }
    }

    public HeroTimeinterval(long value = 0L)
    {
      this.Type = new HeroType(HeroTypes.Timeinterval);
      this.hasValue = true;
      this.Value = value;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      stream.Read(out this.Value);
    }

    public override void Serialize(PackedStream_2 stream)
    {
      stream.Write(this.Value);
    }
  }
}
