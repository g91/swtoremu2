using Hero;

namespace Hero.Types
{
  public class HeroVoid : HeroAnyValue
  {
    public HeroVoid()
    {
      this.Type = new HeroType(HeroTypes.None);
    }
  }
}
