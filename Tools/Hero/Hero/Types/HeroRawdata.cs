using Hero;

namespace Hero.Types
{
  public class HeroRawdata : HeroAnyValue
  {
    public byte[] Data;

    public override string ValueText
    {
      get
      {
        return "--Data--";
      }
    }

    public HeroRawdata(byte[] data)
    {
      this.Type = new HeroType(HeroTypes.Rawdata);
      this.hasValue = true;
      this.Data = data;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      stream.Read(out this.Data);
    }

    public override void Serialize(PackedStream_2 stream)
    {
      stream.Write(this.Data);
    }
  }
}
