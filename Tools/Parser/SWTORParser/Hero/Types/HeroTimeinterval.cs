namespace SWTORParser.Hero.Types
{
    public class HeroTimeinterval : HeroAnyValue
    {
        public long Value;

        public HeroTimeinterval(long value = 0L)
        {
            Type = new HeroType(HeroTypes.Timeinterval);
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