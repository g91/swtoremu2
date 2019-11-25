using Hero.Types;
using System;
using System.IO;

namespace Hero
{
  public class DeserializeLookupList : SerializeStateBase
  {
    public HeroType indexerType;
    public HeroType valueType;
    public bool m_30;

    public DeserializeLookupList(PackedStream_2 stream, int valueState, HeroType defaultIndexerType)
      : base(stream, HeroTypes.LookupList)
    {
      this.valueType = defaultIndexerType;
      this.m_30 = false;
      if (stream.Flags[4])
      {
        if (this.Next == null)
          throw new InvalidDataException("Only a HeroClass can be the root container type");
        else
          throw new NotImplementedException();
      }
      else
      {
        if (valueState != 1)
          throw new InvalidDataException("Invalid value state");
        if (stream.Flags[0])
        {
          ulong num;
          stream.Read(out num);
          if ((long) num != 0L)
            this.indexerType = new HeroType((HeroTypes) num);
        }
        if (!this.GetValueType(ref this.valueType))
          throw new InvalidDataException("Error getting type");
        stream.Read(out this.m_0C, out this.Count);
        if (stream.Style != 8 && stream.Style != 10)
          return;
        this.m_30 = ((int) this.Count & 1) == 1;
        DeserializeLookupList deserializeLookupList = this;
        int num1 = (int) (deserializeLookupList.Count >> 1);
        deserializeLookupList.Count = (uint) num1;
      }
    }

    public bool GetValueType(ref HeroType type)
    {
      if (!this.Stream.Flags[0])
        return true;
      ulong num;
      this.Stream.Read(out num);
      type = new HeroType((HeroTypes) num);
      return true;
    }

    public bool GetKey(out HeroAnyValue key, out int variableId)
    {
      if (this.indexerType.Type == HeroTypes.String || this.indexerType.Type == HeroTypes.None)
        return this.GetKeyString(out key, out variableId);
      else
        return this.GetKeyInt(out key, out variableId);
    }

    public bool GetKeyString(out HeroAnyValue key, out int variableId)
    {
      key = HeroAnyValue.Create(new HeroType(HeroTypes.String));
      if ((int) this.Stream.TransportVersion > 1)
      {
        if ((int) this.Stream.Peek() == 210)
        {
          int num = (int) this.Stream.ReadByte();
          key.Deserialize(this.Stream);
        }
        else
        {
          ulong num;
          this.Stream.Read(out num);
          (key as HeroString).Text = string.Format("{0}", (object) num);
        }
      }
      else if ((int) this.Stream.Peek() == 137)
      {
        key.Deserialize(this.Stream);
      }
      else
      {
        ulong num;
        this.Stream.Read(out num);
        (key as HeroString).Text = string.Format("{0}", (object) num);
      }
      variableId = this.ReadVariableId();
      return true;
    }

    public bool GetKeyInt(out HeroAnyValue key, out int variableId)
    {
      key = HeroAnyValue.Create(this.indexerType);
      if ((int) this.Stream.TransportVersion > 1)
      {
        if ((int) this.Stream.Peek() == 210)
        {
          int num = (int) this.Stream.ReadByte();
          HeroAnyValue heroAnyValue = HeroAnyValue.Create(new HeroType(HeroTypes.String));
          heroAnyValue.Deserialize(this.Stream);
          if (this.indexerType.Type == HeroTypes.Enum)
            (key as HeroEnum).Value = Convert.ToUInt64((heroAnyValue as HeroString).Text);
          else if (this.indexerType.Type == HeroTypes.Integer)
          {
            (key as HeroInt).Value = Convert.ToInt64((heroAnyValue as HeroString).Text);
          }
          else
          {
            if (this.indexerType.Type != HeroTypes.Id)
              throw new InvalidDataException("Invalid key type");
            (key as HeroID).ID = Convert.ToUInt64((heroAnyValue as HeroString).Text);
          }
        }
        else
        {
          ulong num;
          this.Stream.Read(out num);
          if (this.indexerType.Type == HeroTypes.Enum)
            (key as HeroEnum).Value = num;
          else if (this.indexerType.Type == HeroTypes.Integer)
          {
            (key as HeroInt).Value = (long) num;
          }
          else
          {
            if (this.indexerType.Type != HeroTypes.Id)
              throw new InvalidDataException("Invalid key type");
            (key as HeroID).Id = num;
          }
          key.hasValue = true;
        }
      }
      else if ((int) this.Stream.Peek() == 137)
      {
        HeroAnyValue heroAnyValue = HeroAnyValue.Create(new HeroType(HeroTypes.String));
        heroAnyValue.Deserialize(this.Stream);
        if (this.indexerType.Type == HeroTypes.Enum)
          (key as HeroEnum).Value = Convert.ToUInt64((heroAnyValue as HeroString).Text);
        else if (this.indexerType.Type == HeroTypes.Integer)
        {
          (key as HeroInt).Value = Convert.ToInt64((heroAnyValue as HeroString).Text);
        }
        else
        {
          if (this.indexerType.Type != HeroTypes.Id)
            throw new InvalidDataException("Invalid key type");
          (key as HeroID).Id = Convert.ToUInt64((heroAnyValue as HeroString).Text);
        }
      }
      else
      {
        ulong num;
        this.Stream.Read(out num);
        if (this.indexerType.Type == HeroTypes.Enum)
          (key as HeroEnum).Value = num;
        else if (this.indexerType.Type == HeroTypes.Integer)
        {
          (key as HeroInt).Value = (long) num;
        }
        else
        {
          if (this.indexerType.Type != HeroTypes.Id)
            throw new InvalidDataException("Invalid key type");
          (key as HeroID).Id = num;
        }
        key.hasValue = true;
      }
      variableId = this.ReadVariableId();
      return true;
    }
  }
}
