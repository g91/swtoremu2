using SWTORParser.Hero.Definition;

namespace SWTORParser.Hero
{
    public class DefinitionId
    {
        public ulong Id;

        public DefinitionId()
        {
            Id = 0UL;
        }

        public DefinitionId(ulong id)
        {
            Set(id);
        }

        public HeroDefinition Definition
        {
            get { return Gom.Instance.LookupDefinitionId(Id); }
        }

        public static implicit operator HeroDefinition(DefinitionId id)
        {
            return Gom.Instance.LookupDefinitionId(id.Id);
        }

        public static explicit operator ulong(DefinitionId id)
        {
            return id.Id;
        }

        public void Set(ulong id)
        {
            Id = id;
        }

        public override string ToString()
        {
            HeroDefinition heroDefinition = Gom.Instance.LookupDefinitionId(Id);
            if (heroDefinition != null)
                return heroDefinition.ToString();
            else
                return string.Format("0x{0:X8}", Id);
        }
    }
}