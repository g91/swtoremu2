using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NexusToRServer.AreaServer
{
    public static class Awareness
    {
        public static byte[] Get(string Area, string AreaID, string AreaCode, int AwarenessID)
        {
            // TODO (?)
            String FileName = String.Format(@"{0}-{1}-{2}.{3}.aaw", Area, AreaID, AreaCode, AwarenessID);
            String FilePath = @"AreaServer\Awareness\" + FileName;
            if (File.Exists(FilePath))
                return File.ReadAllBytes(FilePath);
            Log.Write(LogLevel.Warning, "Could not find Awareness [{0}]", FileName);
            return (new byte[] { });
        }
    }
}
