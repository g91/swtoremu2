using Hero;

namespace Hero.Types
{
  public class HeroFloat : HeroAnyValue
  {
    public float Value;

    public override string ValueText
    {
      get
      {
        return string.Format("{0}", (object) this.Value);
      }
    }

    public HeroFloat(float value = 0.0f)
    {
      this.Type = new HeroType(HeroTypes.Float);
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
