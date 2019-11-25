namespace SWTORParser.Hero.Types
{
    public class HeroString : HeroAnyValue
    {
        public string Text;

        public HeroString(string str = null)
        {
            Type = new HeroType(HeroTypes.String);
            Text = str;
            hasValue = Text != null;
        }

        public override string ValueText
        {
            get
            {
                if (Text != null)
                    return "\"" + Text + "\"";
                else
                    return "";
            }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            stream.Read(out Text);
        }

        public override void Serialize(PackedStream2 stream)
        {
            stream.Write(Text);
        }

        public override void Unmarshal(string data, bool hasXml = true)
        {
            if (hasXml)
            {
                Unmarshal(GetRoot(data).InnerXml, false);
            }
            else
            {
                Text = data;
                hasValue = true;
            }
        }
    }
}