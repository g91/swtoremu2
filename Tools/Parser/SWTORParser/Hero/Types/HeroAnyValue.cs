using System;
using System.IO;
using System.Xml;

namespace SWTORParser.Hero.Types
{
    public class HeroAnyValue
    {
        public ulong ID;
        public HeroType Type;
        public bool hasValue;

        public HeroAnyValue()
        {
            hasValue = false;
            Type = new HeroType();
        }

        protected HeroAnyValue(HeroType Type)
        {
            this.Type = Type;
        }

        public virtual string ValueText
        {
            get { return null; }
        }

        public virtual void Deserialize(PackedStream2 stream)
        {
            throw new NotImplementedException();
        }

        public virtual void Serialize(PackedStream2 stream)
        {
            throw new NotImplementedException();
        }

        public static HeroType GetTypeFromJStream(PackedStream2 stream)
        {
            ulong num;
            stream.ReadVersion(out num);
            if ((long) num != 0L)
                throw new InvalidDataException("incorrect header token for creating HeroValueType");
            ulong id;
            stream.Read(out id);
            var heroType = new HeroType((HeroTypes) id);
            switch (heroType.Type)
            {
                case HeroTypes.Enum:
                case HeroTypes.Class:
                case HeroTypes.NodeRef:
                    stream.Read(out id);
                    heroType.Id = new DefinitionId(id);
                    break;
                case HeroTypes.List:
                    heroType.Values = GetTypeFromJStream(stream);
                    stream.CheckEnd();
                    break;
                case HeroTypes.LookupList:
                    heroType.Indexer = GetTypeFromJStream(stream);
                    stream.CheckEnd();
                    heroType.Values = GetTypeFromJStream(stream);
                    stream.CheckEnd();
                    break;
            }
            return heroType;
        }

        public static void SetTypeInJStream(PackedStream2 stream, HeroType type)
        {
            stream.WriteVersion(0UL);
            stream.Write((ulong) type.Type);
            switch (type.Type)
            {
                case HeroTypes.List:
                    SetTypeInJStream(stream, type.Values);
                    break;
                case HeroTypes.LookupList:
                    SetTypeInJStream(stream, type.Indexer);
                    SetTypeInJStream(stream, type.Values);
                    break;
                case HeroTypes.Class:
                case HeroTypes.NodeRef:
                    stream.Write(type.Id.Id);
                    break;
            }
        }

        public override string ToString()
        {
            if (!hasValue)
                return Type.ToString();
            string valueText = ValueText;
            if (valueText != null)
                return Type + ": " + valueText;
            else
                return Type + ": null";
        }

        public static HeroAnyValue Create(HeroType type)
        {
            switch (type.Type)
            {
                case HeroTypes.None:
                    return new HeroVoid();
                case HeroTypes.Id:
                    return new HeroID();
                case HeroTypes.Integer:
                    return new HeroInt(0L);
                case HeroTypes.Boolean:
                    return new HeroBool(false);
                case HeroTypes.Float:
                    return new HeroFloat(0.0f);
                case HeroTypes.Enum:
                    return new HeroEnum(type, 0UL);
                case HeroTypes.String:
                    return new HeroString((string) null);
                case HeroTypes.List:
                    return new HeroList(type.Values);
                case HeroTypes.LookupList:
                    return new HeroLookupList(type.Indexer, type.Values);
                case HeroTypes.Class:
                    return new HeroClass(type);
                case HeroTypes.ScriptRef:
                    return new HeroScriptRef(type);
                case HeroTypes.NodeRef:
                    return new HeroNodeRef(type);
                case HeroTypes.Timer:
                    return new HeroTimer();
                case HeroTypes.Vector3:
                    return new HeroVector3(0.0f, 0.0f, 0.0f);
                case HeroTypes.Timeinterval:
                    return new HeroTimeinterval(0L);
                case HeroTypes.Date:
                    return new HeroDate(0L);
                default:
                    throw new InvalidDataException("cannot construct an invalid type");
            }
        }

        public virtual void Unmarshal(string data, bool asXml = true)
        {
        }

        protected XmlNode GetRoot(string data)
        {
            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(data);
            return xmlDocument.SelectSingleNode("v") ?? xmlDocument.FirstChild;
        }
    }
}