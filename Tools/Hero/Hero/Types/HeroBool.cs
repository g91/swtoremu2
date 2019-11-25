using Hero;

namespace Hero.Types
{
  public class HeroBool : HeroAnyValue
  {
    public bool Value;

    public override string ValueText
    {
      get
      {
        return string.Format("{0}", (object) (bool) (this.Value ? true : false));
      }
    }

    public HeroBool(bool value = false)
    {
      this.Type = new HeroType(HeroTypes.Boolean);
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

    public override void Unmarshal(string data, bool asXml = true)
    {
      if (asXml)
        this.Unmarshal(this.GetRoot(data).InnerText, false);
      else if (data.ToLower() == "false")
      {
        this.Value = false;
        this.hasValue = true;
      }
      else
      {
        if (!(data.ToLower() == "true"))
          return;
        this.Value = true;
        this.hasValue = true;
      }
    }
  }
}
