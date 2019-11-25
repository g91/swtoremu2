using Hero;
using System;
using System.Collections.Generic;
using System.IO;

namespace Hero.Definition
{
  public class HeroClassDef : HeroDefinition
  {
    public DefinitionId vers2_18;
    public DefinitionId vers2_20;
    public List<DefinitionId> ParentClasses;
    public List<DefinitionId> Fields;

    public HeroClassDef(byte[] data, int version)
      : base(data, version)
    {
      this.ParentClasses = new List<DefinitionId>();
      this.Fields = new List<DefinitionId>();
      short num1;
      short num2;
      short num3;
      short num4;
      if (version == 1)
      {
        num1 = BitConverter.ToInt16(data, 22);
        num2 = BitConverter.ToInt16(data, 24);
        num3 = BitConverter.ToInt16(data, 26);
        num4 = BitConverter.ToInt16(data, 28);
      }
      else
      {
        if (version != 2)
          throw new InvalidDataException("Invalid version");
        this.vers2_18 = new DefinitionId(BitConverter.ToUInt64(data, 24));
        this.vers2_20 = new DefinitionId(BitConverter.ToUInt64(data, 32));
        num1 = BitConverter.ToInt16(data, 42);
        num2 = BitConverter.ToInt16(data, 44);
        num3 = BitConverter.ToInt16(data, 46);
        num4 = BitConverter.ToInt16(data, 48);
      }
      for (int index = 0; index < (int) num1; ++index)
        this.ParentClasses.Add(new DefinitionId(BitConverter.ToUInt64(data, (int) num2 + 8 * index)));
      for (int index = 0; index < (int) num3; ++index)
        this.Fields.Add(new DefinitionId(BitConverter.ToUInt64(data, (int) num4 + 8 * index)));
    }

    public override string ToString()
    {
      return "Class " + this.Name;
    }

    public HeroFieldDef GetField(string name)
    {
      foreach (DefinitionId definitionId in this.Fields)
      {
        HeroFieldDef heroFieldDef = definitionId.Definition as HeroFieldDef;
        if (heroFieldDef != null && heroFieldDef.Name == name)
          return heroFieldDef;
      }
      foreach (DefinitionId definitionId in this.ParentClasses)
      {
        HeroClassDef heroClassDef = definitionId.Definition as HeroClassDef;
        if (heroClassDef != null)
        {
          HeroFieldDef field = heroClassDef.GetField(name);
          if (field != null)
            return field;
        }
      }
      return (HeroFieldDef) null;
    }
  }
}
