using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NexusToRServer.AreaServer
{
    public static class HackPacks
    {
        public static byte[] Get(string Area, string AreaID, string AreaCode)
        {
            // TODO (?)
            String FileName = String.Format(@"{0}-{1}-{2}.dat", Area, AreaID, AreaCode);
            String FilePath = @"AreaServer\HackPacks\" + FileName;
            if (File.Exists(FilePath))
                return File.ReadAllBytes(FilePath);
            Log.Write(LogLevel.Warning, "Could not find HackPack [{0}]", FileName);
            return (new byte[] { });
        }
    }
}
