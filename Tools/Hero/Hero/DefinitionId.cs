using Hero.Definition;

namespace Hero
{
  public class DefinitionId
  {
    public ulong Id;

    public HeroDefinition Definition
    {
      get
      {
        return GOM.Instance.LookupDefinitionId(this.Id);
      }
    }

    public DefinitionId()
    {
      this.Id = 0UL;
    }

    public DefinitionId(ulong id)
    {
      this.Set(id);
    }

    public static implicit operator HeroDefinition(DefinitionId id)
    {
      return GOM.Instance.LookupDefinitionId(id.Id);
    }

    public static explicit operator ulong(DefinitionId id)
    {
      return id.Id;
    }

    public void Set(ulong id)
    {
      this.Id = id;
    }

    public override string ToString()
    {
      HeroDefinition heroDefinition = GOM.Instance.LookupDefinitionId(this.Id);
      if (heroDefinition != null)
        return heroDefinition.ToString();
      else
        return string.Format("0x{0:X8}", (object) this.Id);
    }
  }
}
