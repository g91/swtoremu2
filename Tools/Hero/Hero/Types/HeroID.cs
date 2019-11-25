using Hero;
using Hero.Definition;
using System;

namespace Hero.Types
{
  public class HeroID : HeroAnyValue
  {
    public ulong Id;

    public override string ValueText
    {
      get
      {
        return this.Id.ToString();
      }
    }

    public HeroID()
    {
      this.Type = new HeroType(HeroTypes.Id);
    }

    public HeroID(ulong value)
    {
      this.Type = new HeroType(HeroTypes.Id);
      this.Id = value;
      this.hasValue = true;
    }

    public HeroID(string name)
    {
      if (!GOM.Instance.DefinitionsByName[HeroDefinition.Types.Node].ContainsKey(name))
        throw new Exception("No node with the specified name exists");
      this.Type = new HeroType(HeroTypes.Id);
      this.Id = GOM.Instance.DefinitionsByName[HeroDefinition.Types.Node][name].Id;
      this.hasValue = true;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      stream.Read(out this.Id);
    }

    public override void Serialize(PackedStream_2 stream)
    {
      stream.Write(this.Id);
    }

    public override void Unmarshal(string data, bool hasXml = true)
    {
      if (hasXml)
      {
        this.Unmarshal(this.GetRoot(data).InnerText, false);
      }
      else
      {
        this.Id = Convert.ToUInt64(data, 10);
        this.hasValue = true;
      }
    }
  }
}
