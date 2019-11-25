using SWTORParser.Hero.Definition;

namespace SWTORParser.Hero.Types
{
    public class HeroEnum : HeroAnyValue
    {
        public ulong Value;

        public HeroEnum()
        {
            Type = new HeroType(HeroTypes.Enum);
            hasValue = false;
        }

        public HeroEnum(HeroType type = null, ulong value = 0UL)
        {
            Type = new HeroType(HeroTypes.Enum);
            if (type != null)
                Type.Id = type.Id;
            hasValue = true;
            Value = value;
        }

        public override string ValueText
        {
            get
            {
                if ((long) Value == 0L)
                    return string.Format("not set", new object[0]);
                var index = (int) ((long) Value - 1L);
                if (Type.Id != null)
                {
                    var heroEnumDef = Type.Id.Definition as HeroEnumDef;
                    if (heroEnumDef != null && index < heroEnumDef.Values.Count)
                        return heroEnumDef.Values[index];
                }
                return string.Format("{0}", index);
            }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            stream.Read(out Value);
        }

        public override void Serialize(PackedStream2 stream)
        {
            stream.Write(Value);
        }
    }
}