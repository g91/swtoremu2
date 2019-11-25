using System;

namespace SWTORParser.Hero
{
    public class SerializeList : SerializeStateBase
    {
        public int index;
        public HeroTypes listType;

        public SerializeList(PackedStream2 stream, int valueState, HeroTypes listType, int Count)
            : base(stream, HeroTypes.List)
        {
            index = 0;
            if (stream.Flags[4])
                throw new NotImplementedException();
            if (stream.Flags[0])
            {
                var num = (ulong) listType;
                stream.Write(num);
            }
            if (stream.Style == 8 || stream.Style == 10)
                stream.Write(Count*2, Count*2);
            else
                stream.Write(Count, Count);
        }

        public void SetFieldIndex(int index, int variableId)
        {
            ++this.index;
            if (Stream.Flags[2])
            {
                Stream.Write((ulong) index);
                this.index = index;
            }
            else if (this.index != index)
                throw new SerializingException("Wrong index");
            WriteVariableId(variableId);
        }
    }
}