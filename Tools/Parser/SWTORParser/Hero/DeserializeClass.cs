using System;
using System.IO;

namespace SWTORParser.Hero
{
    public class DeserializeClass : SerializeStateBase
    {
        public ulong m_28;
        public int m_30;
        public int m_34;
        public object m_38;

        public DeserializeClass(PackedStream2 stream, int valueState)
            : base(stream, HeroTypes.Class)
        {
            m_28 = 0UL;
            m_30 = m_34 = 0;
            m_38 = null;
            if (stream.Flags[4])
            {
                if (valueState == 0)
                    return;
                if (valueState != 1)
                    throw new InvalidDataException("Invalid value state");
                if (Next != null)
                    throw new NotImplementedException();
                ulong num;
                Stream.Read(out num);
                throw new NotImplementedException();
            }
            else
            {
                if (valueState != 1)
                    throw new InvalidDataException("Invalid value state");
                stream.Read(out m_0C, out Count);
            }
        }

        public void ReadFieldData(out UInt64 fieldId, ref UInt32 type, ref Int32 variableId, out Int32 d)
        {
            switch (Stream.Style)
            {
                case 7:
                    throw new InvalidDataException("Unable to get field id");
                case 8:
                    throw new InvalidDataException("Unable to get field id");
                case 9:
                case 10:
                    throw new InvalidDataException("Unable to get field id");
                default:
                    Int64 num1;
                    Stream.Read(out num1);
                    fieldId = m_28 + (UInt64) num1;
                    if (Stream.Flags[0])
                    {
                        UInt64 num2;
                        Stream.Read(out num2);
                        type = (UInt32) num2;
                    }
                    variableId = ReadVariableId();
                    d = 1;
                    m_28 = fieldId;
                    break;
            }
        }
    }
}