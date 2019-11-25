using System.Xml;
using SWTORParser.Hero.Definition;

namespace SWTORParser.Hero.Types
{
    public class HeroClass : HeroAnyValue
    {
        public VariableList Variables;

        public HeroClass()
        {
            Type = new HeroType(HeroTypes.Class);
            hasValue = false;
            Variables = new VariableList();
        }

        public HeroClass(HeroType type = null)
        {
            Type = new HeroType(HeroTypes.Class);
            Variables = new VariableList();
            if (type != null)
                Type.Id = type.Id;
            hasValue = false;
        }

        public override string ValueText
        {
            get { return "--Data--"; }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            Variables = new VariableList();
            var deserializeClass = new DeserializeClass(stream, 1);
            for (uint index = 0U; index < deserializeClass.Count; ++index)
            {
                uint type1 = 0U;
                int variableId = 0;
                ulong fieldId;
                int d;
                deserializeClass.ReadFieldData(out fieldId, ref type1, ref variableId, out d);
                if (d != 2)
                {
                    var type2 = new HeroType((HeroTypes) type1);
                    var field = new DefinitionId(fieldId);
                    if (field.Definition != null)
                    {
                        var heroFieldDef = field.Definition as HeroFieldDef;
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
                    HeroAnyValue heroAnyValue = Create(type2);
                    heroAnyValue.Deserialize(stream);
                    Variables.Add(new Variable(field, variableId, heroAnyValue));
                }
            }
        }

        public override void Serialize(PackedStream2 stream)
        {
            int count = 0;
            if (Variables != null)
                count = Variables.Count;
            var serializeClass = new SerializeClass(stream, 1, count);
            for (int index = 0; index < count; ++index)
            {
                serializeClass.WriteFieldData(Variables[index].Field.Id, Variables[index].Value.Type.Type,
                                              Variables[index].VariableId);
                Variables[index].Value.Serialize(stream);
            }
        }

        public override void Unmarshal(string data, bool withV = true)
        {
            XmlNode xmlNode1 = GetRoot(data).SelectSingleNode("node");
            if (xmlNode1 == null)
                throw new SerializingException("node tag not found");
            var heroClassDef = Type.Id.Definition as HeroClassDef;
            for (XmlNode xmlNode2 = xmlNode1.FirstChild; xmlNode2 != null; xmlNode2 = xmlNode2.NextSibling)
            {
                if (xmlNode2.Name == "f")
                {
                    string name = xmlNode2.Attributes["name"].Value;
                    HeroFieldDef field = heroClassDef.GetField(name);
                    if (field != null)
                    {
                        HeroAnyValue heroAnyValue = Create(field.FieldType);
                        heroAnyValue.Unmarshal("<v>" + xmlNode2.InnerXml + "</v>", true);
                        Variables.Add(new Variable(new DefinitionId(field.Id), 0, heroAnyValue));
                    }
                }
            }
        }
    }
}