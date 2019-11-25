using Hero;
using Hero.Definition;

namespace Hero.Types
{
  public class HeroEnum : HeroAnyValue
  {
    public ulong Value;

    public override string ValueText
    {
      get
      {
        if ((long) this.Value == 0L)
          return string.Format("not set", new object[0]);
        int index = (int) ((long) this.Value - 1L);
        if (this.Type.Id != null)
        {
          HeroEnumDef heroEnumDef = this.Type.Id.Definition as HeroEnumDef;
          if (heroEnumDef != null && index < heroEnumDef.Values.Count)
            return heroEnumDef.Values[index];
        }
        return string.Format("{0}", (object) index);
      }
    }

    public HeroEnum()
    {
      this.Type = new HeroType(HeroTypes.Enum);
      this.hasValue = false;
    }

    public HeroEnum(HeroType type = null, ulong value = 0UL)
    {
      this.Type = new HeroType(HeroTypes.Enum);
      if (type != null)
        this.Type.Id = type.Id;
      this.hasValue = true;
      this.Value = value;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      stream.Read(out this.Value);
    }

    public override void Serialize(PackedStream_2 stream)
    {
      stream.Write(this.Value);
    }
  }
}
