using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Security.Cryptography;

using NexusToRServer.NET;

using CSInteropKeys;

namespace NexusToRServer.TimeServer
{
    class Handler
    {
        private static TCPServer Server;

        public static void Start(int sPort)
        {
            Server = new TCPServer(sPort);
            Log.Write(LogLevel.Info, "TimeServer listening on port {0}", sPort);
            Server.eventClientConnected += new ClientConnected(ClientConnected);
            Server.eventPacketReceived += new PacketReceived(PacketReceived);
            Server.eventClientDisconnected += new ClientDisconnected(ClientDisconnected);
        }

        static void ClientConnected(TCPClient pClient)
        {
            Log.Write(LogLevel.Client, "Client '{0}' connected to TimeServer", pClient.ClientID);
            TORGameClient MyClient = new TORGameClient(pClient);
        }

        static void PacketReceived(TCPClient pClient)
        {
            if (pClient.RecvBytes == 29) // Hello packet
                return;

            if (pClient.RecvBytes != 9)
                Log.Write(LogLevel.Warning, "Unkown TimePacket:\n{0}", pClient.Buffer.ToHEX(pClient.RecvBytes));

            byte[] pBuffer = new byte[pClient.RecvBytes];
            Array.Copy(pClient.Buffer, pBuffer, pClient.RecvBytes);
            MemoryStream Stream = new MemoryStream(pBuffer);
            EndianBinaryReader Reader = new EndianBinaryReader(MiscUtil.Conversion.BigEndianBitConverter.Little, Stream);

            Reader.ReadByte(); // Length
            UInt16 Unk01 = Reader.ReadUInt16();
            UInt32 Stamp = Reader.ReadUInt32(); // This is incrementing
            UInt16 Terminator = Reader.ReadUInt16();

            MemoryStream OutStream = new MemoryStream();
            EndianBinaryWriter Writer = new EndianBinaryWriter(MiscUtil.Conversion.BigEndianBitConverter.Little, OutStream);

            Writer.Write((byte)0x10); // Length
            Writer.Write(Unk01);
            Writer.Write(Stamp);
            Writer.Write(Terminator);
            Writer.Write((UInt16)0x00); // TODO: Fix that
            Writer.Write(Stamp);
            Writer.Write(Terminator);

            TCPClient oClient = new TCPClient(pClient);
            oClient.Buffer = OutStream.ToArray();

            Writer.Dispose();
            OutStream.Dispose();
            Stream.Dispose();
            Reader.Dispose();
            Server.Send(oClient);
        }

        static void ClientDisconnected(TCPClient pClient)
        {
            Log.Write(LogLevel.Warning, "Client '{0}' disconnected from TimeServer", pClient.ClientID);

            pClient.Dispose();
        }
    }
}