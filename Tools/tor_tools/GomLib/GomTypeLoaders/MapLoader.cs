using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.GomTypeLoaders
{
    class MapLoader : IGomTypeLoader
    {
        public GomTypeId SupportedType { get { return GomTypeId.Map; } }

        public GomType Load(GomBinaryReader reader, bool fromGom)
        {
            var t = new GomTypes.Map();
            if (fromGom)
            {
                t.KeyType = GomTypeLoader.Load(reader, fromGom);
                t.ValueType = GomTypeLoader.Load(reader, fromGom);
            }
            return t;
        }
    }
}
