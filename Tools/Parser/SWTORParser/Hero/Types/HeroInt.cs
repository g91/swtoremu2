namespace SWTORParser.Hero.Types
{
    public class HeroInt : HeroAnyValue
    {
        public long Value;

        public HeroInt(long value = 0L)
        {
            Type = new HeroType(HeroTypes.Integer);
            hasValue = true;
            Value = value;
        }

        public override string ValueText
        {
            get { return string.Format("{0}", Value); }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            stream.Read(out Value);
        }

        public override void Serialize(PackedStream2 stream)
        {
            stream.Write(Value);
        }
    }
}