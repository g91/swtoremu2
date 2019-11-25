using System;
using System.Collections.Generic;
using System.IO;

namespace SWTORParser.Hero.Definition
{
    public class HeroEnumDef : HeroDefinition
    {
        public List<string> Values;

        public HeroEnumDef(byte[] data, int version)
            : base(data, version)
        {
            Values = new List<string>();
            short num1;
            int num2;
            if (version == 1)
            {
                num1 = BitConverter.ToInt16(data, 20);
                num2 = BitConverter.ToInt16(data, 22);
            }
            else
            {
                if (version != 2)
                    throw new InvalidDataException("Invalid version");
                num1 = BitConverter.ToInt16(data, 24);
                num2 = BitConverter.ToInt16(data, 26);
            }
            for (int index = 0; index < (int) num1; ++index)
                Values.Add(GetString(BitConverter.ToUInt16(data, num2 + index*2)));
        }

        public override string ToString()
        {
            return "enum " + Name;
        }
    }
}