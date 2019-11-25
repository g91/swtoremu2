namespace SWTORParser.Hero.Types
{
    public class HeroGuid : HeroAnyValue
    {
        public ulong GUID;

        public HeroGuid(ulong GUID = 0UL)
        {
            Type = new HeroType(HeroTypes.Guid);
            hasValue = true;
            this.GUID = GUID;
        }

        public override string ValueText
        {
            get { return string.Format("{0:X8}", GUID); }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            stream.Read(out GUID);
        }

        public override void Serialize(PackedStream2 stream)
        {
            stream.Write(GUID);
        }
    }
}