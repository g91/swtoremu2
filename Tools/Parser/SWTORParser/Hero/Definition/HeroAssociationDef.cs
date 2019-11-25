using System;
using System.IO;

namespace SWTORParser.Hero.Definition
{
    public class HeroAssociationDef : HeroDefinition
    {
        public ushort Flags;

        public HeroAssociationDef(byte[] data, int version)
            : base(data, version)
        {
            if (version == 1)
            {
                Flags = BitConverter.ToUInt16(data, 20);
            }
            else
            {
                if (version != 2)
                    throw new InvalidDataException("Invalid version");
                Flags = BitConverter.ToUInt16(data, 24);
            }
        }

        public override string ToString()
        {
            return "association " + Name;
        }
    }
}