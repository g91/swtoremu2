using Hero;

namespace Hero.Types
{
  public class HeroDate : HeroAnyValue
  {
    public long Value;

    public override string ValueText
    {
      get
      {
        return string.Format("{0}", (object) this.Value);
      }
    }

    public HeroDate(long value = 0L)
    {
      this.Type = new HeroType(HeroTypes.Date);
      this.hasValue = true;
      this.Value = value;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      stream.Read(out this.Value);
      if (this.Value != 0L)
        return;
      this.Value = -2305320741190498156L;
    }

    public override void Serialize(PackedStream_2 stream)
    {
      stream.Write(this.Value);
    }
  }
}
