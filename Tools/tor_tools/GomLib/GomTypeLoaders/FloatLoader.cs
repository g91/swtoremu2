using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.GomTypeLoaders
{
    class FloatLoader : IGomTypeLoader
    {
        public GomTypeId SupportedType { get { return GomTypeId.Float; } }

        public GomType Load(GomBinaryReader reader, bool fromGom)
        {
            return new GomTypes.Float();
        }
    }
}
