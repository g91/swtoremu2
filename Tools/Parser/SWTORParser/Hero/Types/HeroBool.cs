namespace SWTORParser.Hero.Types
{
    public class HeroBool : HeroAnyValue
    {
        public bool Value;

        public HeroBool(bool value = false)
        {
            Type = new HeroType(HeroTypes.Boolean);
            hasValue = true;
            Value = value;
        }

        public override string ValueText
        {
            get { return string.Format("{0}", (Value ? true : false)); }
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

        public override void Unmarshal(string data, bool asXml = true)
        {
            if (asXml)
                Unmarshal(GetRoot(data).InnerText, false);
            else if (data.ToLower() == "false")
            {
                Value = false;
                hasValue = true;
            }
            else
            {
                if (!(data.ToLower() == "true"))
                    return;
                Value = true;
                hasValue = true;
            }
        }
    }
}