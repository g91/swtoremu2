using System.IO;

namespace SWTORParser.Hero
{
    public class HeroType
    {
        public DefinitionId Id;
        public HeroTypes Type;

        public HeroType()
        {
            Type = HeroTypes.None;
        }

        public HeroType(HeroTypes type)
        {
            Type = type;
        }

        protected HeroType(OmegaStream stream)
        {
            Type = (HeroTypes) stream.ReadByte();
            switch (Type)
            {
                case HeroTypes.Enum:
                case HeroTypes.Class:
                case HeroTypes.NodeRef:
                    Id = new DefinitionId(stream.ReadULong());
                    break;
                case HeroTypes.List:
                    Values = new HeroType(stream);
                    break;
                case HeroTypes.LookupList:
                    Indexer = new HeroType(stream);
                    Values = new HeroType(stream);
                    break;
            }
        }

        public HeroType Values { get; set; }

        public HeroType Indexer { get; set; }

        public static HeroType Create(byte[] data, ushort offset, ushort length)
        {
            return new HeroType(new OmegaStream(new MemoryStream(data, offset, length)));
        }

        public void SetValuesType(HeroTypes type)
        {
            Values = new HeroType(type);
        }

        public override string ToString()
        {
            switch (Type)
            {
                case HeroTypes.None:
                    return "";

                case HeroTypes.Enum:
                    return Id == null ? "enum" : Id.ToString();

                case HeroTypes.List:
                    return Values == null ? "list" : "list of " + Values;

                case HeroTypes.LookupList:
                    if (Indexer == null && Values == null)
                        return "lookuplist";

                    if (Indexer != null && Values == null)
                        return "lookuplist indexed by " + Indexer;

                    if (Indexer == null && Values != null)
                        return "lookuplist of " + Values;
                    
                    return "lookuplist indexed by " + Indexer + " of " + Values;

                case HeroTypes.Class:
                    return Id == null ? "class" : Id.ToString();

                case HeroTypes.NodeRef:
                    if ((long) Id.Id == 0L)
                        return "noderef";
                    
                    return "noderef of " + Id;

                default:
                    return Type.ToString();
            }
        }
    }
}