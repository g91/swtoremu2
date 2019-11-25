using Hero;
using System;
using System.IO;
using System.Xml;

namespace Hero.Types
{
  public class HeroAnyValue
  {
    public bool hasValue;
    public HeroType Type;
    public ulong ID;

    public virtual string ValueText
    {
      get
      {
        return (string) null;
      }
    }

    public HeroAnyValue()
    {
      this.hasValue = false;
      this.Type = new HeroType();
    }

    protected HeroAnyValue(HeroType Type)
    {
      this.Type = Type;
    }

    public virtual void Deserialize(PackedStream_2 stream)
    {
      throw new NotImplementedException();
    }

    public virtual void Serialize(PackedStream_2 stream)
    {
      throw new NotImplementedException();
    }

    public static HeroType GetTypeFromJStream(PackedStream_2 stream)
    {
      ulong num;
      stream.ReadVersion(out num);
      if ((long) num != 0L)
        throw new InvalidDataException("incorrect header token for creating HeroValueType");
      ulong id;
      stream.Read(out id);
      HeroType heroType = new HeroType((HeroTypes) id);
      switch (heroType.Type)
      {
        case HeroTypes.Enum:
        case HeroTypes.Class:
        case HeroTypes.NodeRef:
          stream.Read(out id);
          heroType.Id = new DefinitionId(id);
          break;
        case HeroTypes.List:
          heroType.Values = HeroAnyValue.GetTypeFromJStream(stream);
          stream.CheckEnd();
          break;
        case HeroTypes.LookupList:
          heroType.Indexer = HeroAnyValue.GetTypeFromJStream(stream);
          stream.CheckEnd();
          heroType.Values = HeroAnyValue.GetTypeFromJStream(stream);
          stream.CheckEnd();
          break;
      }
      return heroType;
    }

    public static void SetTypeInJStream(PackedStream_2 stream, HeroType type)
    {
      stream.WriteVersion(0UL);
      stream.Write((ulong) type.Type);
      switch (type.Type)
      {
        case HeroTypes.List:
          HeroAnyValue.SetTypeInJStream(stream, type.Values);
          break;
        case HeroTypes.LookupList:
          HeroAnyValue.SetTypeInJStream(stream, type.Indexer);
          HeroAnyValue.SetTypeInJStream(stream, type.Values);
          break;
        case HeroTypes.Class:
        case HeroTypes.NodeRef:
          stream.Write(type.Id.Id);
          break;
      }
    }

    public override string ToString()
    {
      if (!this.hasValue)
        return this.Type.ToString();
      string valueText = this.ValueText;
      if (valueText != null)
        return this.Type.ToString() + ": " + valueText;
      else
        return this.Type.ToString() + ": null";
    }

    public static HeroAnyValue Create(HeroType type)
    {
      switch (type.Type)
      {
        case HeroTypes.None:
          return (HeroAnyValue) new HeroVoid();
        case HeroTypes.Id:
          return (HeroAnyValue) new HeroID();
        case HeroTypes.Integer:
          return (HeroAnyValue) new HeroInt(0L);
        case HeroTypes.Boolean:
          return (HeroAnyValue) new HeroBool(false);
        case HeroTypes.Float:
          return (HeroAnyValue) new HeroFloat(0.0f);
        case HeroTypes.Enum:
          return (HeroAnyValue) new HeroEnum(type, 0UL);
        case HeroTypes.String:
          return (HeroAnyValue) new HeroString((string) null);
        case HeroTypes.List:
          return (HeroAnyValue) new HeroList(type.Values);
        case HeroTypes.LookupList:
          return (HeroAnyValue) new HeroLookupList(type.Indexer, type.Values);
        case HeroTypes.Class:
          return (HeroAnyValue) new HeroClass(type);
        case HeroTypes.ScriptRef:
          return (HeroAnyValue) new HeroScriptRef(type);
        case HeroTypes.NodeRef:
          return (HeroAnyValue) new HeroNodeRef(type);
        case HeroTypes.Timer:
          return (HeroAnyValue) new HeroTimer();
        case HeroTypes.Vector3:
          return (HeroAnyValue) new HeroVector3(0.0f, 0.0f, 0.0f);
        case HeroTypes.Timeinterval:
          return (HeroAnyValue) new HeroTimeinterval(0L);
        case HeroTypes.Date:
          return (HeroAnyValue) new HeroDate(0L);
        default:
          throw new InvalidDataException("cannot construct an invalid type");
      }
    }

    public virtual void Unmarshal(string data, bool asXml = true)
    {
    }

    protected XmlNode GetRoot(string data)
    {
      XmlDocument xmlDocument = new XmlDocument();
      xmlDocument.LoadXml(data);
      return xmlDocument.SelectSingleNode("v") ?? xmlDocument.FirstChild;
    }
  }
}
