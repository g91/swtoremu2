using Hero;

namespace Hero.Types
{
  public class HeroString : HeroAnyValue
  {
    public string Text;

    public override string ValueText
    {
      get
      {
        if (this.Text != null)
          return "\"" + this.Text + "\"";
        else
          return "";
      }
    }

    public HeroString(string str = null)
    {
      this.Type = new HeroType(HeroTypes.String);
      this.Text = str;
      this.hasValue = this.Text != null;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      stream.Read(out this.Text);
    }

    public override void Serialize(PackedStream_2 stream)
    {
      stream.Write(this.Text);
    }

    public override void Unmarshal(string data, bool hasXml = true)
    {
      if (hasXml)
      {
        this.Unmarshal(this.GetRoot(data).InnerXml, false);
      }
      else
      {
        this.Text = data;
        this.hasValue = true;
      }
    }
  }
}
