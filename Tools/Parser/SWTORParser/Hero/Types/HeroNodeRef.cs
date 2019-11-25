namespace SWTORParser.Hero.Types
{
    public class HeroNodeRef : HeroAnyValue
    {
        public HeroNodeRef(HeroType type = null)
        {
            Type = new HeroType(HeroTypes.NodeRef);
            if (type != null)
                Type.Id = type.Id;
            hasValue = Type.Id != null;
        }

        public override string ValueText
        {
            get { return Type.Id.ToString(); }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            if (Type.Id == null)
                Type.Id = new DefinitionId();
            stream.Read(out Type.Id.Id);
        }

        public override void Serialize(PackedStream2 stream)
        {
            if (Type.Id == null)
                throw new SerializingException("Cannot serialize a non-reference");
            stream.Write(Type.Id.Id);
        }
    }
}