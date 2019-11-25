using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.GomTypes
{
    public class Script : GomType
    {
        public Script() : base(GomTypeId.Script) { }

        public override string ToString()
        {
            return "script";
        }

        public override object ReadData(GomBinaryReader reader)
        {
            throw new NotImplementedException();
        }
    }
}
