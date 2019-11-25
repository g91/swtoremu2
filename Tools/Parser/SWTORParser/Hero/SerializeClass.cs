using System;
using System.IO;

namespace SWTORParser.Hero
{
    public class SerializeClass : SerializeStateBase
    {
        public ulong m_28;
        public int m_30;
        public int m_34;
        public object m_38;

        public SerializeClass(PackedStream2 stream, int valueState, int count)
            : base(stream, HeroTypes.Class)
        {
            m_28 = 0UL;
            m_30 = m_34 = 0;
            m_38 = null;
            if (stream.Flags[4])
                throw new NotImplementedException();
            stream.Write(count, count);
        }

        public void WriteFieldData(ulong fieldId, HeroTypes type, int variableId)
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
                    Stream.Write((long) fieldId - (long) m_28);
                    m_28 = fieldId;
                    if (Stream.Flags[0])
                        Stream.Write((ulong) type);
                    WriteVariableId(variableId);
                    break;
            }
        }
    }
}