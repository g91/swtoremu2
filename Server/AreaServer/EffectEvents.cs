using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NexusToRServer.AreaServer
{
    public static class EffectEvents
    {
        public static byte[] Get(string Area, string AreaID, string AreaCode, int AwarenessID)
        {
            // TODO (?)
            String FileName = String.Format(@"{0}-{1}-{2}.{3}.aeff", Area, AreaID, AreaCode, AwarenessID);
            String FilePath = @"AreaServer\EffectEvent\" + FileName;
            if (File.Exists(FilePath))
                return File.ReadAllBytes(FilePath);
            Log.Write(LogLevel.Warning, "Could not find EffectEvents [{0}]", FileName);
            return (new byte[] { });
        }
    }
}
