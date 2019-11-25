using System;
using System.IO;
using SWTORParser.Hero.Types;

namespace SWTORParser.Hero
{
    public class DeserializeLookupList : SerializeStateBase
    {
        public HeroType indexerType;
        public bool m_30;
        public HeroType valueType;

        public DeserializeLookupList(PackedStream2 stream, int valueState, HeroType defaultIndexerType)
            : base(stream, HeroTypes.LookupList)
        {
            valueType = defaultIndexerType;
            m_30 = false;
            if (stream.Flags[4])
            {
                if (Next == null)
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
                        indexerType = new HeroType((HeroTypes) num);
                }
                if (!GetValueType(ref valueType))
                    throw new InvalidDataException("Error getting type");
                stream.Read(out m_0C, out Count);
                if (stream.Style != 8 && stream.Style != 10)
                    return;
                m_30 = ((int) Count & 1) == 1;
                DeserializeLookupList deserializeLookupList = this;
                var num1 = (int) (deserializeLookupList.Count >> 1);
                deserializeLookupList.Count = (uint) num1;
            }
        }

        public bool GetValueType(ref HeroType type)
        {
            if (!Stream.Flags[0])
                return true;
            ulong num;
            Stream.Read(out num);
            type = new HeroType((HeroTypes) num);
            return true;
        }

        public bool GetKey(out HeroAnyValue key, out int variableId)
        {
            if (indexerType.Type == HeroTypes.String || indexerType.Type == HeroTypes.None)
                return GetKeyString(out key, out variableId);
            else
                return GetKeyInt(out key, out variableId);
        }

        public bool GetKeyString(out HeroAnyValue key, out int variableId)
        {
            key = HeroAnyValue.Create(new HeroType(HeroTypes.String));
            if (Stream.TransportVersion > 1)
            {
                if (Stream.Peek() == 210)
                {
                    int num = Stream.ReadByte();
                    key.Deserialize(Stream);
                }
                else
                {
                    ulong num;
                    Stream.Read(out num);
                    (key as HeroString).Text = string.Format("{0}", num);
                }
            }
            else if (Stream.Peek() == 137)
            {
                key.Deserialize(Stream);
            }
            else
            {
                ulong num;
                Stream.Read(out num);
                (key as HeroString).Text = string.Format("{0}", num);
            }
            variableId = ReadVariableId();
            return true;
        }

        public bool GetKeyInt(out HeroAnyValue key, out int variableId)
        {
            key = HeroAnyValue.Create(indexerType);
            if (Stream.TransportVersion > 1)
            {
                if (Stream.Peek() == 210)
                {
                    int num = Stream.ReadByte();
                    HeroAnyValue heroAnyValue = HeroAnyValue.Create(new HeroType(HeroTypes.String));
                    heroAnyValue.Deserialize(Stream);
                    if (indexerType.Type == HeroTypes.Enum)
                        (key as HeroEnum).Value = Convert.ToUInt64((heroAnyValue as HeroString).Text);
                    else if (indexerType.Type == HeroTypes.Integer)
                    {
                        (key as HeroInt).Value = Convert.ToInt64((heroAnyValue as HeroString).Text);
                    }
                    else
                    {
                        if (indexerType.Type != HeroTypes.Id)
                            throw new InvalidDataException("Invalid key type");
                        (key as HeroID).ID = Convert.ToUInt64((heroAnyValue as HeroString).Text);
                    }
                }
                else
                {
                    ulong num;
                    Stream.Read(out num);
                    if (indexerType.Type == HeroTypes.Enum)
                        (key as HeroEnum).Value = num;
                    else if (indexerType.Type == HeroTypes.Integer)
                    {
                        (key as HeroInt).Value = (long) num;
                    }
                    else
                    {
                        if (indexerType.Type != HeroTypes.Id)
                            throw new InvalidDataException("Invalid key type");
                        (key as HeroID).Id = num;
                    }
                    key.hasValue = true;
                }
            }
            else if (Stream.Peek() == 137)
            {
                HeroAnyValue heroAnyValue = HeroAnyValue.Create(new HeroType(HeroTypes.String));
                heroAnyValue.Deserialize(Stream);
                if (indexerType.Type == HeroTypes.Enum)
                    (key as HeroEnum).Value = Convert.ToUInt64((heroAnyValue as HeroString).Text);
                else if (indexerType.Type == HeroTypes.Integer)
                {
                    (key as HeroInt).Value = Convert.ToInt64((heroAnyValue as HeroString).Text);
                }
                else
                {
                    if (indexerType.Type != HeroTypes.Id)
                        throw new InvalidDataException("Invalid key type");
                    (key as HeroID).Id = Convert.ToUInt64((heroAnyValue as HeroString).Text);
                }
            }
            else
            {
                ulong num;
                Stream.Read(out num);
                if (indexerType.Type == HeroTypes.Enum)
                    (key as HeroEnum).Value = num;
                else if (indexerType.Type == HeroTypes.Integer)
                {
                    (key as HeroInt).Value = (long) num;
                }
                else
                {
                    if (indexerType.Type != HeroTypes.Id)
                        throw new InvalidDataException("Invalid key type");
                    (key as HeroID).Id = num;
                }
                key.hasValue = true;
            }
            variableId = ReadVariableId();
            return true;
        }
    }
}