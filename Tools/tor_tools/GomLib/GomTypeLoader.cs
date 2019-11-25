using System;
using System.Collections.Generic;

namespace GomLib
{
    public static class GomTypeLoader
    {
        private static Dictionary<GomTypeId, GomTypeLoaders.IGomTypeLoader> gomTypeLoaderMap;

        private static void AddLoader(GomTypeLoaders.IGomTypeLoader loader)
        {
            gomTypeLoaderMap.Add(loader.SupportedType, loader);
        }

        static GomTypeLoader()
        {
            gomTypeLoaderMap = new Dictionary<GomTypeId, GomTypeLoaders.IGomTypeLoader>();
            AddLoader(new GomTypeLoaders.UInt64Loader());
            AddLoader(new GomTypeLoaders.IntegerLoader());
            AddLoader(new GomTypeLoaders.BooleanLoader());
            AddLoader(new GomTypeLoaders.FloatLoader());
            AddLoader(new GomTypeLoaders.EnumLoader());
            AddLoader(new GomTypeLoaders.StringLoader());
            AddLoader(new GomTypeLoaders.ListLoader());
            AddLoader(new GomTypeLoaders.MapLoader());
            AddLoader(new GomTypeLoaders.EmbeddedClassLoader());
            // Array
            // Table
            // Cubic
            AddLoader(new GomTypeLoaders.ScriptLoader());
            AddLoader(new GomTypeLoaders.ClassRefLoader());
            AddLoader(new GomTypeLoaders.TimerLoader());
            AddLoader(new GomTypeLoaders.VectorLoader());
            AddLoader(new GomTypeLoaders.TimeSpanLoader());
            AddLoader(new GomTypeLoaders.TimeLoader());
        }

        public static GomType Load(GomBinaryReader reader, bool fromGom = true)
        {
            GomTypeId typeId = (GomTypeId)reader.ReadByte();
            GomTypeLoaders.IGomTypeLoader gomTypeLoader;
            if (!gomTypeLoaderMap.TryGetValue(typeId, out gomTypeLoader))
            {
                throw new InvalidOperationException(String.Format("Unknown GomType with Type ID {0}", (byte)typeId));
            }

            return gomTypeLoader.Load(reader, fromGom);
        }
    }
}
