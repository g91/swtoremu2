using Hero;
using System.Collections.Generic;

namespace Hero.Types
{
  public class HeroList : HeroAnyValue
  {
    public List<HeroVarId> Data;
    public int nextId;

    public override string ValueText
    {
      get
      {
        if (this.Data == null)
          return "{ }";
        string str = "{ ";
        foreach (HeroVarId heroVarId in this.Data)
          str = str + heroVarId.Value.ValueText + ", ";
        return str + " }";
      }
    }

    public HeroList(HeroType type = null)
    {
      this.Type = new HeroType(HeroTypes.List);
      this.Type.Values = type;
      this.nextId = 0;
    }

    public int GetNextId()
    {
      ++this.nextId;
      return this.nextId;
    }

    public void Add<T>(T value) where T : HeroAnyValue
    {
      if (this.Data == null)
        this.Data = new List<HeroVarId>();
      this.Data.Add(new HeroVarId(this.GetNextId(), (HeroAnyValue) value));
    }

    public override void Deserialize(PackedStream_2 stream)
    {
      this.hasValue = true;
      this.Data = new List<HeroVarId>();
      DeserializeList deserializeList = new DeserializeList(stream, 1);
      if (this.Type.Values == null)
        this.Type.SetValuesType(deserializeList.listType);
      for (uint index1 = 0U; index1 < deserializeList.Count; ++index1)
      {
        uint index2;
        bool b;
        int variableId;
        deserializeList.GetFieldIndex(out index2, out b, out variableId);
        HeroAnyValue heroAnyValue = HeroAnyValue.Create(this.Type.Values);
        heroAnyValue.Deserialize(stream);
        this.Data.Add(new HeroVarId(variableId, heroAnyValue));
        if (variableId > this.nextId)
          this.nextId = variableId;
      }
    }

    public override void Serialize(PackedStream_2 stream)
    {
      int Count = 0;
      if (this.Data != null)
        Count = this.Data.Count;
      SerializeList serializeList = new SerializeList(stream, 1, this.Type.Values.Type, Count);
      for (int index = 0; index < Count; ++index)
      {
        serializeList.SetFieldIndex(index, this.Data[index].VarId);
        this.Data[index].Value.Serialize(stream);
      }
    }
  }
}
