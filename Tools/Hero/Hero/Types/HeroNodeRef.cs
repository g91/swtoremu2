using Hero;

namespace Hero.Types
{
  public class HeroNodeRef : HeroAnyValue
  {
    public override string ValueText
    {
      get
      {
        return this.Type.Id.ToString();
      }
    }

    public HeroNodeRef(HeroType type = null)
    {
      this.Type = new HeroType(HeroTypes.NodeRef);
      if (type != null)
        this.Type.Id = type.Id;
      this.hasValue = this.Type.Id != null;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      if (this.Type.Id == null)
        this.Type.Id = new DefinitionId();
      stream.Read(out this.Type.Id.Id);
    }

    public override void Serialize(PackedStream_2 stream)
    {
      if (this.Type.Id == null)
        throw new SerializingException("Cannot serialize a non-reference");
      stream.Write(this.Type.Id.Id);
    }
  }
}
