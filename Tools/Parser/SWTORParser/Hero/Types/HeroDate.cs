namespace SWTORParser.Hero.Types
{
    public class HeroDate : HeroAnyValue
    {
        public long Value;

        public HeroDate(long value = 0L)
        {
            Type = new HeroType(HeroTypes.Date);
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
            if (Value != 0L)
                return;
            Value = -2305320741190498156L;
        }

        public override void Serialize(PackedStream2 stream)
        {
            stream.Write(Value);
        }
    }
}