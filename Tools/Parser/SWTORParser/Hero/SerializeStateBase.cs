using System;

namespace SWTORParser.Hero
{
    public class SerializeStateBase
    {
        public uint Count;
        public HeroTypes HeroType;
        protected SerializeStateBase Next;
        public PackedStream2 Stream;
        protected uint m_0C;

        public SerializeStateBase(PackedStream2 stream, HeroTypes heroType)
        {
            HeroType = heroType;
            Next = null;
            Stream = stream;
            m_0C = 0U;
            Count = 0U;
            Next = stream.State;
            stream.State = this;
        }

        public int ReadVariableId()
        {
            if (!Stream.Flags[1] || Stream.TransportVersion >= 5)
                return 0;

            UInt64 num;
            Stream.Read(out num);
            return (Int32) num;
        }

        public void WriteVariableId(Int32 variableId)
        {
            if (!Stream.Flags[1])
                return;

            Stream.Write((UInt64)variableId);
        }
    }
}