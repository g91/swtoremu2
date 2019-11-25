using System;
using System.Collections.Generic;
using SWTORParser.Hero.Types;

namespace SWTORParser.Hero
{
    public class IDSpace
    {
        protected ulong current;
        protected ulong end;
        protected Dictionary<ulong, HeroAnyValue> objects;
        protected ulong start;

        public IDSpace(ulong Start, ulong End)
        {
            start = Start;
            end = End;
            current = Start;
            objects = new Dictionary<ulong, HeroAnyValue>();
        }

        public ulong Get()
        {
            if ((long) current == (long) end)
                throw new Exception("ID space exhausted");
            ulong num = current;
            ++current;
            return num;
        }

        public void Add(HeroAnyValue obj)
        {
            if (obj.ID < start || obj.ID >= end)
                throw new Exception("Object has a wrong ID for this space");
            objects[obj.ID] = obj;
        }
    }
}