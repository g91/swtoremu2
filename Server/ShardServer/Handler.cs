using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Security.Cryptography;

using NexusToRServer.NET;

using CSInteropKeys;

namespace NexusToRServer.ShardServer
{
    class Handler
    {
        private static List<TORGameClient> GameClients;
        private static TCPServer Server;

        public static void Start(int sPort)
        {
            Server = new TCPServer(sPort);
            Log.Write(LogLevel.Info, "ShardServer listening on port {0}", sPort);

            GameClients = new List<TORGameClient>();

            Server.eventClientConnected += new ClientConnected(ClientConnected);
            Server.eventPacketReceived += new PacketReceived(PacketReceived);
            Server.eventClientDisconnected += new ClientDisconnected(ClientDisconnected);
        }

        static void ClientConnected(TCPClient pClient)
        {
            Log.Write(LogLevel.Client, "Client '{0}' connected to Shard01", pClient.ClientID);
            TORGameClient MyClient = new TORGameClient(pClient);
            GameClients.Add(MyClient);
        }

        static void PacketReceived(TCPClient pClient)
        {
            var sClient = GameClients.Find(s => s.SessionID == pClient.ClientID);

            try
            {
                if (pClient.RecvBytes > 0)
                {
                    byte[] pBuffer = new byte[pClient.RecvBytes];
                    Array.Copy(pClient.Buffer, pBuffer, pClient.RecvBytes);
                    TORGamePacketHandler.InitPacket(pBuffer, sClient);
                }
            }
            catch (Exception ex)
            {
                Log.Write(LogLevel.Error, "{0}", ex.ToString());
            }
        }

        static void ClientDisconnected(TCPClient pClient)
        {
            var sClient = GameClients.Find(s => s.SessionID == pClient.ClientID);

            Log.Write(LogLevel.Warning, "Client '{0}' disconnected from Shard01", pClient.ClientID);

            GameClients.Remove(sClient);

            sClient.Dispose();
            pClient.Dispose();
        }
    }
}