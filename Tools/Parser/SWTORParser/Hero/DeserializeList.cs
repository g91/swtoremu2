using System;
using System.IO;

namespace SWTORParser.Hero
{
    public class DeserializeList : SerializeStateBase
    {
        public UInt32 Index;
        public HeroTypes ListType;
        public Boolean M30;

        public DeserializeList(PackedStream2 stream, int valueState)
            : base(stream, HeroTypes.List)
        {
            Index = 0U;
            M30 = false;
            if (stream.Flags[4])
            {
                if (Next == null)
                    throw new InvalidDataException("Only a HeroClass can be the root container type");
            }
            else
            {
                if (valueState != 1)
                    throw new InvalidDataException("Invalid value state");

                if (stream.Flags[0])
                {
                    UInt64 num;
                    stream.Read(out num);
                    ListType = (HeroTypes) num;
                }
            }

            stream.Read(out m_0C, out Count);
            if (stream.Style != 8 && stream.Style != 10)
                return;

            M30 = (Count & 1) == 1;
            Count >>= 1;
        }

        public void GetFieldIndex(out UInt32 index, out Boolean b, out Int32 variableId)
        {
            ++Index;
            if (M30)
            {
                UInt64 num;
                Stream.Read(out num);
                b = ((long) num & 1L) == 1L;
                index = (UInt32) (num >> 1);
            }
            else
            {
                b = false;
                if (Stream.Flags[2])
                {
                    UInt64 num;
                    Stream.Read(out num);
                    index = (UInt32) num;
                }
                else
                    index = Index;
            }
            variableId = ReadVariableId();
        }
    }
}