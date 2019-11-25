namespace SWTORParser.Hero.Types
{
    public class HeroVoid : HeroAnyValue
    {
        public HeroVoid()
        {
            Type = new HeroType(HeroTypes.None);
        }
    }
}