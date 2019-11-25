using Hero;
using System.Collections.Generic;
using System.Xml;

namespace Hero.Types
{
  public class HeroLookupList : HeroAnyValue
  {
    public Dictionary<HeroVarId, HeroAnyValue> Data;
    public int nextId;

    public override string ValueText
    {
      get
      {
        if (this.Data == null)
          return "[ ]";
        string str = "[ ";
        foreach (KeyValuePair<HeroVarId, HeroAnyValue> keyValuePair in this.Data)
          str = str + keyValuePair.Key.Value.ValueText + ": " + keyValuePair.Value.ValueText + ", ";
        return str + " ]";
      }
    }

    public HeroAnyValue this[string key]
    {
      get
      {
        foreach (KeyValuePair<HeroVarId, HeroAnyValue> keyValuePair in this.Data)
        {
          if (keyValuePair.Key.CompareTo(key) == 0)
            return this.Data[keyValuePair.Key];
        }
        return (HeroAnyValue) null;
      }
      set
      {
        foreach (KeyValuePair<HeroVarId, HeroAnyValue> keyValuePair in this.Data)
        {
          if (keyValuePair.Key.CompareTo(key) == 0)
            this.Data[keyValuePair.Key] = value;
        }
        this.Data[new HeroVarId(0, (HeroAnyValue) new HeroString(key))] = value;
      }
    }

    public HeroLookupList(HeroType key = null, HeroType values = null)
    {
      this.Type = new HeroType(HeroTypes.LookupList);
      this.Type.Indexer = key;
      this.Type.Values = values;
      this.nextId = 0;
    }

    public int GetNextId()
    {
      ++this.nextId;
      return this.nextId;
    }

    public void Add<T1, T2>(T1 key, T2 value) where T1 : HeroAnyValue where T2 : HeroAnyValue
    {
      if (this.Data == null)
        this.Data = new Dictionary<HeroVarId, HeroAnyValue>();
      this.Data[new HeroVarId(this.GetNextId(), (HeroAnyValue) key)] = (HeroAnyValue) value;
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      this.Data = new Dictionary<HeroVarId, HeroAnyValue>();
      HeroType defaultIndexerType = new HeroType(HeroTypes.None);
      if (this.Type.Indexer != null)
        defaultIndexerType = this.Type.Indexer;
      DeserializeLookupList deserializeLookupList = new DeserializeLookupList(stream, 1, defaultIndexerType);
      if (this.Type.Indexer == null || this.Type.Indexer.Type == HeroTypes.None)
        this.Type.Indexer = deserializeLookupList.indexerType;
      else
        deserializeLookupList.indexerType = this.Type.Indexer;
      if (this.Type.Values == null)
        this.Type.Values = deserializeLookupList.valueType;
      else
        deserializeLookupList.valueType = this.Type.Values;
      for (ulong index = 0UL; index < (ulong) deserializeLookupList.Count; ++index)
      {
        HeroAnyValue key;
        int variableId;
        deserializeLookupList.GetKey(out key, out variableId);
        HeroAnyValue heroAnyValue = HeroAnyValue.Create(this.Type.Values);
        heroAnyValue.Deserialize(stream);
        this.Data[new HeroVarId(variableId, key)] = heroAnyValue;
        if (variableId > this.nextId)
          this.nextId = variableId;
      }
    }

    public override void Serialize(PackedStream_2 stream)
    {
      int Count = 0;
      if (this.Data != null)
        Count = this.Data.Count;
      SerializeLookupList serializeLookupList = new SerializeLookupList(stream, 1, this.Type, Count);
      if (this.Data == null)
        return;
      foreach (KeyValuePair<HeroVarId, HeroAnyValue> keyValuePair in this.Data)
      {
        serializeLookupList.SetKey(keyValuePair.Key.Value, keyValuePair.Key.VarId);
        keyValuePair.Value.Serialize(stream);
      }
    }

    public override void Unmarshal(string data, bool asXml = true)
    {
      XmlNode root = this.GetRoot(data);
      this.Data = new Dictionary<HeroVarId, HeroAnyValue>();
      HeroAnyValue heroAnyValue1 = (HeroAnyValue) null;
      for (XmlNode xmlNode = root.FirstChild; xmlNode != null; xmlNode = xmlNode.NextSibling)
      {
        if (xmlNode.Name == "k")
        {
          heroAnyValue1 = HeroAnyValue.Create(this.Type.Indexer);
          heroAnyValue1.Unmarshal("<v>" + xmlNode.InnerText + "</v>", true);
        }
        if (xmlNode.Name == "e")
        {
          HeroAnyValue heroAnyValue2 = HeroAnyValue.Create(this.Type.Values);
          heroAnyValue2.Unmarshal("<v>" + xmlNode.InnerText + "</v>", true);
          this.Data[new HeroVarId(0, heroAnyValue1)] = heroAnyValue2;
          heroAnyValue1 = (HeroAnyValue) null;
        }
      }
      this.hasValue = true;
    }
  }
}
