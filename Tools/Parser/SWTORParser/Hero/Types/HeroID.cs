using System;
using SWTORParser.Hero.Definition;

namespace SWTORParser.Hero.Types
{
    public class HeroID : HeroAnyValue
    {
        public ulong Id;

        public HeroID()
        {
            Type = new HeroType(HeroTypes.Id);
        }

        public HeroID(ulong value)
        {
            Type = new HeroType(HeroTypes.Id);
            Id = value;
            hasValue = true;
        }

        public HeroID(string name)
        {
            if (!Gom.Instance.DefinitionsByName[HeroDefinition.Types.Node].ContainsKey(name))
                throw new Exception("No node with the specified name exists");
            Type = new HeroType(HeroTypes.Id);
            Id = Gom.Instance.DefinitionsByName[HeroDefinition.Types.Node][name].Id;
            hasValue = true;
        }

        public override string ValueText
        {
            get { return Id.ToString(); }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            stream.Read(out Id);
        }

        public override void Serialize(PackedStream2 stream)
        {
            stream.Write(Id);
        }

        public override void Unmarshal(string data, bool hasXml = true)
        {
            if (hasXml)
            {
                Unmarshal(GetRoot(data).InnerText, false);
            }
            else
            {
                Id = Convert.ToUInt64(data, 10);
                hasValue = true;
            }
        }
    }
}