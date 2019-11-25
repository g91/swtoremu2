using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace NexusToRServer
{
    class Program
    {
        static void Main(string[] args)
        {
            Log.Init("NexusToR.log", LogLevel.Client | LogLevel.Debug | LogLevel.Error | LogLevel.Info | LogLevel.Warning, false);

            LoginServer.Handler.Start(7979);
            ShardServer.Handler.Start(20060);
            TimeServer.Handler.Start(20066);

            while (true)
                Thread.Sleep(1);
        }
    }
}
