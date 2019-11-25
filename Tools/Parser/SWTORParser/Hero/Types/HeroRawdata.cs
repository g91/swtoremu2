namespace SWTORParser.Hero.Types
{
    public class HeroRawdata : HeroAnyValue
    {
        public byte[] Data;

        public HeroRawdata(byte[] data)
        {
            Type = new HeroType(HeroTypes.Rawdata);
            hasValue = true;
            Data = data;
        }

        public override string ValueText
        {
            get { return "--Data--"; }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            stream.Read(out Data);
        }

        public override void Serialize(PackedStream2 stream)
        {
            stream.Write(Data);
        }
    }
}