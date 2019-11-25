using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.GomTypeLoaders
{
    class TimeLoader : IGomTypeLoader
    {
        public GomTypeId SupportedType { get { return GomTypeId.Time; } }

        public GomType Load(GomBinaryReader reader, bool fromGom)
        {
            return new GomTypes.Time();
        }
    }
}
