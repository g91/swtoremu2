using System;
using SWTORParser.Hero.Types;

namespace SWTORParser.Hero
{
    public class SerializeLookupList : SerializeStateBase
    {
        public HeroTypes indexerType;
        public bool m_30;
        public HeroTypes valueType;

        public SerializeLookupList(PackedStream2 stream, int valueState, HeroType type, int Count)
            : base(stream, HeroTypes.LookupList)
        {
            m_30 = false;
            if (stream.Flags[4])
                throw new NotImplementedException();
            if (stream.Flags[0])
                stream.Write((ulong) type.Indexer.Type);
            SetValueType(type.Values.Type);
            if (stream.Style == 8 || stream.Style == 10)
                stream.Write(Count*2, Count*2);
            else
                stream.Write(Count, Count);
        }

        public void SetValueType(HeroTypes type)
        {
            if (!Stream.Flags[0])
                return;
            Stream.Write((ulong) type);
        }

        public void SetKey(HeroAnyValue key, int variableId)
        {
            switch (key.Type.Type)
            {
                case HeroTypes.Id:
                    SetKeyInt((key as HeroID).Id, variableId);
                    break;
                case HeroTypes.Integer:
                    SetKeyInt((ulong) (key as HeroInt).Value, variableId);
                    break;
                case HeroTypes.Enum:
                    SetKeyInt((key as HeroEnum).Value, variableId);
                    break;
                case HeroTypes.String:
                    SetKeyString((key as HeroString).Text, variableId);
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        public void SetKeyString(string key, int variableId)
        {
            if (Stream.TransportVersion > 1)
            {
                Stream.WriteByte(210);
                Stream.Write(key);
            }
            else
            {
                Stream.WriteByte(137);
                Stream.Write(key);
            }
            WriteVariableId(variableId);
        }

        public void SetKeyInt(ulong key, int variableId)
        {
            Stream.Write(key);
            Stream.Write(variableId);
        }
    }
}