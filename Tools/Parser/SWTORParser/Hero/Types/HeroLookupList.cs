using System.Collections.Generic;
using System.Xml;

namespace SWTORParser.Hero.Types
{
    public class HeroLookupList : HeroAnyValue
    {
        public Dictionary<HeroVarId, HeroAnyValue> Data;
        public int nextId;

        public HeroLookupList(HeroType key = null, HeroType values = null)
        {
            Type = new HeroType(HeroTypes.LookupList);
            Type.Indexer = key;
            Type.Values = values;
            nextId = 0;
        }

        public override string ValueText
        {
            get
            {
                if (Data == null)
                    return "[ ]";
                string str = "[ ";
                foreach (var keyValuePair in Data)
                    str = str + keyValuePair.Key.Value.ValueText + ": " + keyValuePair.Value.ValueText + ", ";
                return str + " ]";
            }
        }

        public HeroAnyValue this[string key]
        {
            get
            {
                foreach (var keyValuePair in Data)
                {
                    if (keyValuePair.Key.CompareTo(key) == 0)
                        return Data[keyValuePair.Key];
                }
                return null;
            }
            set
            {
                foreach (var keyValuePair in Data)
                {
                    if (keyValuePair.Key.CompareTo(key) == 0)
                        Data[keyValuePair.Key] = value;
                }
                Data[new HeroVarId(0, new HeroString(key))] = value;
            }
        }

        public int GetNextId()
        {
            ++nextId;
            return nextId;
        }

        public void Add<T1, T2>(T1 key, T2 value) where T1 : HeroAnyValue where T2 : HeroAnyValue
        {
            if (Data == null)
                Data = new Dictionary<HeroVarId, HeroAnyValue>();
            Data[new HeroVarId(GetNextId(), key)] = value;
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            Data = new Dictionary<HeroVarId, HeroAnyValue>();
            var defaultIndexerType = new HeroType(HeroTypes.None);
            if (Type.Indexer != null)
                defaultIndexerType = Type.Indexer;
            var deserializeLookupList = new DeserializeLookupList(stream, 1, defaultIndexerType);
            if (Type.Indexer == null || Type.Indexer.Type == HeroTypes.None)
                Type.Indexer = deserializeLookupList.indexerType;
            else
                deserializeLookupList.indexerType = Type.Indexer;
            if (Type.Values == null)
                Type.Values = deserializeLookupList.valueType;
            else
                deserializeLookupList.valueType = Type.Values;
            for (ulong index = 0UL; index < (ulong) deserializeLookupList.Count; ++index)
            {
                HeroAnyValue key;
                int variableId;
                deserializeLookupList.GetKey(out key, out variableId);
                HeroAnyValue heroAnyValue = Create(Type.Values);
                heroAnyValue.Deserialize(stream);
                Data[new HeroVarId(variableId, key)] = heroAnyValue;
                if (variableId > nextId)
                    nextId = variableId;
            }
        }

        public override void Serialize(PackedStream2 stream)
        {
            int Count = 0;
            if (Data != null)
                Count = Data.Count;
            var serializeLookupList = new SerializeLookupList(stream, 1, Type, Count);
            if (Data == null)
                return;
            foreach (var keyValuePair in Data)
            {
                serializeLookupList.SetKey(keyValuePair.Key.Value, keyValuePair.Key.VarId);
                keyValuePair.Value.Serialize(stream);
            }
        }

        public override void Unmarshal(string data, bool asXml = true)
        {
            XmlNode root = GetRoot(data);
            Data = new Dictionary<HeroVarId, HeroAnyValue>();
            HeroAnyValue heroAnyValue1 = null;
            for (XmlNode xmlNode = root.FirstChild; xmlNode != null; xmlNode = xmlNode.NextSibling)
            {
                if (xmlNode.Name == "k")
                {
                    heroAnyValue1 = Create(Type.Indexer);
                    heroAnyValue1.Unmarshal("<v>" + xmlNode.InnerText + "</v>", true);
                }
                if (xmlNode.Name == "e")
                {
                    HeroAnyValue heroAnyValue2 = Create(Type.Values);
                    heroAnyValue2.Unmarshal("<v>" + xmlNode.InnerText + "</v>", true);
                    Data[new HeroVarId(0, heroAnyValue1)] = heroAnyValue2;
                    heroAnyValue1 = null;
                }
            }
            hasValue = true;
        }
    }
}