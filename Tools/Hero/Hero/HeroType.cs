using System.IO;

namespace Hero
{
  public class HeroType
  {
    public HeroTypes Type;
    public DefinitionId Id;
    private HeroType indexer;
    private HeroType values;

    public HeroType Values
    {
      get
      {
        return this.values;
      }
      set
      {
        this.values = value;
      }
    }

    public HeroType Indexer
    {
      get
      {
        return this.indexer;
      }
      set
      {
        this.indexer = value;
      }
    }

    public HeroType()
    {
      this.Type = HeroTypes.None;
    }

    public HeroType(HeroTypes type)
    {
      this.Type = type;
    }

    protected HeroType(OmegaStream stream)
    {
      this.Type = (HeroTypes) stream.ReadByte();
      switch (this.Type)
      {
        case HeroTypes.Enum:
        case HeroTypes.Class:
        case HeroTypes.NodeRef:
          this.Id = new DefinitionId(stream.ReadULong());
          break;
        case HeroTypes.List:
          this.Values = new HeroType(stream);
          break;
        case HeroTypes.LookupList:
          this.Indexer = new HeroType(stream);
          this.Values = new HeroType(stream);
          break;
      }
    }

    public static HeroType Create(byte[] data, ushort offset, ushort length)
    {
      return new HeroType(new OmegaStream((Stream) new MemoryStream(data, (int) offset, (int) length)));
    }

    public void SetValuesType(HeroTypes type)
    {
      this.Values = new HeroType(type);
    }

    public override string ToString()
    {
      switch (this.Type)
      {
        case HeroTypes.None:
          return "";
        case HeroTypes.Enum:
          if (this.Id == null)
            return "enum";
          else
            return this.Id.ToString();
        case HeroTypes.List:
          if (this.Values == null)
            return "list";
          else
            return "list of " + this.Values.ToString();
        case HeroTypes.LookupList:
          if (this.Indexer == null && this.Values == null)
            return "lookuplist";
          if (this.Indexer != null && this.Values == null)
            return "lookuplist indexed by " + this.Indexer.ToString();
          if (this.Indexer == null && this.Values != null)
            return "lookuplist of " + this.Values.ToString();
          else
            return "lookuplist indexed by " + this.Indexer.ToString() + " of " + this.Values.ToString();
        case HeroTypes.Class:
          if (this.Id == null)
            return "class";
          else
            return this.Id.ToString();
        case HeroTypes.NodeRef:
          if ((long) this.Id.Id == 0L)
            return "noderef";
          else
            return "noderef of " + this.Id.ToString();
        default:
          return ((object) this.Type).ToString();
      }
    }
  }
}
