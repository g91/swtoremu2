namespace SWTORParser.Hero.Types
{
    public class HeroFloat : HeroAnyValue
    {
        public float Value;

        public HeroFloat(float value = 0.0f)
        {
            Type = new HeroType(HeroTypes.Float);
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