using Hero;
using Hero.Definition;
using System.Xml;

namespace Hero.Types
{
  public class HeroClass : HeroAnyValue
  {
    public VariableList Variables;

    public override string ValueText
    {
      get
      {
        return "--Data--";
      }
    }

    public HeroClass()
    {
      this.Type = new HeroType(HeroTypes.Class);
      this.hasValue = false;
      this.Variables = new VariableList();
    }

    public HeroClass(HeroType type = null)
    {
      this.Type = new HeroType(HeroTypes.Class);
      this.Variables = new VariableList();
      if (type != null)
        this.Type.Id = type.Id;
      this.hasValue = false;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      this.Variables = new VariableList();
      DeserializeClass deserializeClass = new DeserializeClass(stream, 1);
      for (uint index = 0U; index < deserializeClass.Count; ++index)
      {
        uint type1 = 0U;
        int variableId = 0;
        ulong fieldId;
        int d;
        deserializeClass.ReadFieldData(out fieldId, ref type1, ref variableId, out d);
        if (d != 2)
        {
          HeroType type2 = new HeroType((HeroTypes) type1);
          DefinitionId field = new DefinitionId(fieldId);
          if (field.Definition != null)
          {
            HeroFieldDef heroFieldDef = field.Definition as HeroFieldDef;
            switch (heroFieldDef.FieldType.Type)
            {
              case HeroTypes.Enum:
              case HeroTypes.ScriptRef:
                type2.Id = heroFieldDef.FieldType.Id;
                break;
              case HeroTypes.LookupList:
                type2 = heroFieldDef.FieldType;
                break;
            }
          }
          HeroAnyValue heroAnyValue = HeroAnyValue.Create(type2);
          heroAnyValue.Deserialize(stream);
          this.Variables.Add(new Variable(field, variableId, heroAnyValue));
        }
      }
    }

    public override void Serialize(PackedStream_2 stream)
    {
      int count = 0;
      if (this.Variables != null)
        count = this.Variables.Count;
      SerializeClass serializeClass = new SerializeClass(stream, 1, count);
      for (int index = 0; index < count; ++index)
      {
        serializeClass.WriteFieldData(this.Variables[index].Field.Id, this.Variables[index].Value.Type.Type, this.Variables[index].VariableId);
        this.Variables[index].Value.Serialize(stream);
      }
    }

    public override void Unmarshal(string data, bool withV = true)
    {
      XmlNode xmlNode1 = this.GetRoot(data).SelectSingleNode("node");
      if (xmlNode1 == null)
        throw new SerializingException("node tag not found");
      HeroClassDef heroClassDef = this.Type.Id.Definition as HeroClassDef;
      for (XmlNode xmlNode2 = xmlNode1.FirstChild; xmlNode2 != null; xmlNode2 = xmlNode2.NextSibling)
      {
        if (xmlNode2.Name == "f")
        {
          string name = xmlNode2.Attributes["name"].Value;
          HeroFieldDef field = heroClassDef.GetField(name);
          if (field != null)
          {
            HeroAnyValue heroAnyValue = HeroAnyValue.Create(field.FieldType);
            heroAnyValue.Unmarshal("<v>" + xmlNode2.InnerXml + "</v>", true);
            this.Variables.Add(new Variable(new DefinitionId(field.Id), 0, heroAnyValue));
          }
        }
      }
    }
  }
}
