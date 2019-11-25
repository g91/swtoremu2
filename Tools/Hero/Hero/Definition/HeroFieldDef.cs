using Hero;
using System;
using System.IO;

namespace Hero.Definition
{
  public class HeroFieldDef : HeroDefinition
  {
    public HeroType FieldType;

    public HeroFieldDef(byte[] data, int version)
      : base(data, version)
    {
      if (version == 1)
      {
        this.FieldType = HeroType.Create(data, BitConverter.ToUInt16(data, 24), BitConverter.ToUInt16(data, 22));
      }
      else
      {
        if (version != 2)
          throw new InvalidDataException("Invalid version");
        this.FieldType = HeroType.Create(data, BitConverter.ToUInt16(data, 28), BitConverter.ToUInt16(data, 26));
      }
    }

    public override string ToString()
    {
      return "Field " + this.Name + " as " + this.FieldType.ToString();
    }
  }
}
