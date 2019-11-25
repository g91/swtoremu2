using Hero;

namespace Hero.Types
{
  public class HeroAssociation : HeroAnyValue
  {
    public override string ValueText
    {
      get
      {
        return "";
      }
    }

    public HeroAssociation(HeroType type = null)
    {
      this.Type = new HeroType(HeroTypes.Association);
      if (type != null)
        this.Type.Id = type.Id;
      this.hasValue = false;
    }
  }
}
