using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.GomTypes
{
    public class UInt64 : GomType
    {
        public UInt64() : base(GomTypeId.UInt64) { }

        public override string ToString()
        {
            return "ulong";
        }

        public override object ReadData(GomBinaryReader reader)
        {
            ulong val = reader.ReadNumber();

            return val;
        }
    }
}
