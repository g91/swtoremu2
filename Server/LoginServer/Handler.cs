using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Security.Cryptography;

using CSInteropKeys;

// NEEDS TO BE REWRITTEN 
// BLAH
namespace NexusToRServer.LoginServer
{
    class Handler
    {
        private static List<Router> LoginClients;
        private static TCPServer Server;

        public static void Start(int sPort)
        {
            Server = new TCPServer(sPort);
            Log.Write(LogLevel.Info, "LoginServer listening on port {0}", sPort);

            LoginClients = new List<Router>();

            Server.eventClientConnected += new ClientConnected(ClientConnected);
            Server.eventPacketReceived += new PacketReceived(PacketReceived);
            Server.eventClientDisconnected += new ClientDisconnected(ClientDisconnected);
        }

        static void ClientConnected(TCPClient pClient)
        {
            Log.Write(LogLevel.Client, "Client '{0}' connected to LoginServer", pClient.ClientID);
            Router pRouter = new Router(pClient);
            LoginClients.Add(pRouter);
        }

        static void PacketReceived(TCPClient pClient)
        {
            var sClient = LoginClients.Find(s => s.ClientID == pClient.ClientID);
            sClient.ReceivedPacket(pClient.Buffer, pClient.RecvBytes);

        }

        static void ClientDisconnected(TCPClient pClient)
        {
            var sClient = LoginClients.Find(s => s.ClientID == pClient.ClientID);
            
            Log.Write(LogLevel.Warning, "Client '{0}' disconnected from LoginServer", pClient.ClientID);

            sClient.Dispose();
            pClient.Dispose();
        }
    }
}