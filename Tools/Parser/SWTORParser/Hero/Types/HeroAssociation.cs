namespace SWTORParser.Hero.Types
{
    public class HeroAssociation : HeroAnyValue
    {
        public HeroAssociation(HeroType type = null)
        {
            Type = new HeroType(HeroTypes.Association);
            if (type != null)
                Type.Id = type.Id;
            hasValue = false;
        }

        public override string ValueText
        {
            get { return ""; }
        }
    }
}