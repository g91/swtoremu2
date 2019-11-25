using Hero.Types;
using System;

namespace Hero
{
  public class SerializeLookupList : SerializeStateBase
  {
    public HeroTypes indexerType;
    public HeroTypes valueType;
    public bool m_30;

    public SerializeLookupList(PackedStream_2 stream, int valueState, HeroType type, int Count)
      : base(stream, HeroTypes.LookupList)
    {
      this.m_30 = false;
      if (stream.Flags[4])
        throw new NotImplementedException();
      if (stream.Flags[0])
        stream.Write((ulong) type.Indexer.Type);
      this.SetValueType(type.Values.Type);
      if (stream.Style == 8 || stream.Style == 10)
        stream.Write(Count * 2, Count * 2);
      else
        stream.Write(Count, Count);
    }

    public void SetValueType(HeroTypes type)
    {
      if (!this.Stream.Flags[0])
        return;
      this.Stream.Write((ulong) type);
    }

    public void SetKey(HeroAnyValue key, int variableId)
    {
      switch (key.Type.Type)
      {
        case HeroTypes.Id:
          this.SetKeyInt((key as HeroID).Id, variableId);
          break;
        case HeroTypes.Integer:
          this.SetKeyInt((ulong) (key as HeroInt).Value, variableId);
          break;
        case HeroTypes.Enum:
          this.SetKeyInt((key as HeroEnum).Value, variableId);
          break;
        case HeroTypes.String:
          this.SetKeyString((key as HeroString).Text, variableId);
          break;
        default:
          throw new NotImplementedException();
      }
    }

    public void SetKeyString(string key, int variableId)
    {
      if ((int) this.Stream.TransportVersion > 1)
      {
        this.Stream.WriteByte((byte) 210);
        this.Stream.Write(key);
      }
      else
      {
        this.Stream.WriteByte((byte) 137);
        this.Stream.Write(key);
      }
      this.WriteVariableId(variableId);
    }

    public void SetKeyInt(ulong key, int variableId)
    {
      this.Stream.Write(key);
      this.Stream.Write((long) variableId);
    }
  }
}
