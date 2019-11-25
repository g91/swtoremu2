using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.GomTypeLoaders
{
    class ListLoader : IGomTypeLoader
    {
        public GomTypeId SupportedType { get { return GomTypeId.List; } }

        public GomType Load(GomBinaryReader reader, bool fromGom)
        {
            var result = new GomTypes.List();

            if (fromGom)
            {
                result.ContainedType = GomTypeLoader.Load(reader, fromGom);
            }

            return result;
        }
    }
}
