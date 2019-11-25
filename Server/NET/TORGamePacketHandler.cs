using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using MiscUtil.Conversion;
using NexusToRServer.NET.Packets.Client;

using ComponentAce.Compression.Libs.zlib;

namespace NexusToRServer.NET
{
    public static class TORGamePacketHandler
    {
        public static bool VerifyChecksum(byte[] pBuffer, int pChecksum, int index = 0)
        {
            if ((byte)pChecksum == (pBuffer[index + 0] ^ pBuffer[index + 1] ^ pBuffer[index + 2] ^ pBuffer[index + 3] ^ pBuffer[index + 4]))
                return true;
            return false;
        }

        public static byte[] Decompress(byte[] pBuffer, ZStream iStream)
        {
            byte[] rBuff = new byte[pBuffer.Length + 4];
            Array.Copy(pBuffer, 0, rBuff, 0, pBuffer.Length);

            rBuff[rBuff.Length - 4] = 0x00;
            rBuff[rBuff.Length - 3] = 0x00;
            rBuff[rBuff.Length - 2] = 0xFF;
            rBuff[rBuff.Length - 1] = 0xFF;

            iStream.total_in = 0;
            iStream.total_out = 0;

            iStream.next_in = rBuff;
            iStream.next_in_index = 0;
            iStream.avail_in = rBuff.Length;

            MemoryStream lStream = new MemoryStream();

            do
            {
                byte[] oBuff = new byte[pBuffer.Length * 8];

                iStream.next_out = oBuff;
                iStream.next_out_index = 0;
                iStream.avail_out = pBuffer.Length * 8;

                int ret = iStream.inflate(2);

                if (ret != 0)
                {
                    Log.Write(LogLevel.Error, "Inflate error [{0}]:\n{1}", ret, iStream.msg);
                    break;
                }

                lStream.Write(oBuff, 0, (pBuffer.Length * 8) - iStream.avail_out);
            }
            while (iStream.avail_in != 0 || iStream.avail_out == 0);
            byte[] rBASD = lStream.ToArray();

            lStream.Dispose();

            return rBASD;
        }

        public static void HandlePacket(byte[] Data, byte Module, PacketType Type, UInt32 Unk01, TORGameClient Client)
        {
            // TODO: Check for packet drop

            IPacket iPacket = null;
            ClientState State = Client.State;

            switch (State)
            {
                case ClientState.CONNECTING:
                    switch (Type)
                    {
                        case PacketType.ConnectionHandshake:
                            iPacket = new ConnectionHandshake();
                            break;
                        default:
                            Log.Write(LogLevel.Warning, "Received Unknown Packet [{0:X}] on State '{1}'\n{2}", Type, State.ToString(), Data.ToHEX());
                            break;
                    }
                    break;
                case ClientState.CONNECTED:
                    switch (Type)
                    {
                        case PacketType.ObjectReply:
                            iPacket = new ObjectReply();
                            break;
                        case PacketType.Ping:
                            iPacket = new Ping();
                            break;
                        default:
                            Log.Write(LogLevel.Warning, "Received Unknown Packet [{0:X}] on State '{1}'\n{2}", Type, State.ToString(), Data.ToHEX());
                            break;
                    }
                    break;
                case ClientState.AUTHED:
                    switch (Type)
                    {
                        case PacketType.CreateCharacterRequest:
                            Log.Write(LogLevel.Warning, "\n{0}", Data.ToHEX());
                            iPacket = new CreateCharacterRequest();
                            break;
                        case PacketType.ObjectReply:
                            iPacket = new ObjectReply();
                            break;
                        case PacketType.ServiceRequest:
                            iPacket = new ServiceRequest();
                            break;
                        case PacketType.RequestClose:
                            iPacket = new RequestClose();
                            break;
                        case PacketType.TimeRequesterRequest:
                            iPacket = new TimeRequesterRequest();
                            break;
                        case PacketType.HackNotifyData:
                            iPacket = new HackNotifyData();
                            break;
                        case PacketType.CMsgC26464A9:
                            iPacket = new CMsgC26464A9();
                            break;
                        case PacketType.CMsg7CB9A193:
                            iPacket = new CMsg7CB9A193();
                            break;
                        case PacketType.ModulesList:
                            iPacket = new ModulesList();
                            break;
                        case PacketType.AreaModulesList:
                            iPacket = new AreaModulesList();
                            break;
                        case PacketType.SetTrackingInfo:
                            iPacket = new SetTrackingInfo();
                            break;
                        case PacketType.CharacterListRequest:
                            iPacket = new CharacterListRequest();
                            break;
                        case PacketType.SelectCharacterRequest:
                            iPacket = new SelectCharacterRequest();
                            break;
                        case PacketType.Ping:
                            iPacket = new Ping();
                            break;
                        default:
                            Log.Write(LogLevel.Warning, "Received Unknown Packet [{0:X}] on State '{1}'\n{2}", Type, State.ToString(), Data.ToHEX());
                            break;
                    }
                    break;
                case ClientState.IN_GAME:
                    switch (Type)
                    {
                        case PacketType.RequestClose:
                            iPacket = new RequestClose();
                            break;
                        case PacketType.SetTrackingInfo:
                            iPacket = new SetTrackingInfo();
                            break;
                        case PacketType.Ping:
                            iPacket = new Ping();
                            break;
                        // TODO: Implement Game Packets
                        default:
                            Log.Write(LogLevel.Warning, "Received Unknown Packet [{0:X}] on State '{1}'\n{2}", Type, State.ToString(), Data.ToHEX());
                            break;
                    }
                    break;
            }

            if (iPacket != null)
            {
                iPacket.SetClient(Client);
                iPacket.SetBuffers(Data);
                //Log.Write(LogLevel.EDebug, "{0}", Data.ToHEX());
                iPacket.Read();
                iPacket.Run();
            }
            
        }

        public static void InitPacket(byte[] inBuffer, TORGameClient Client)
        {
            if (Client.State == ClientState.CONNECTING)
            {
                //Log.Write(LogLevel.Debug, "Received an unencrypted packet");

                // Packet is not encrypted
                byte Module = 0xFF;
                PacketType Type = (PacketType)inBuffer[0];
                UInt32 Unk01 = 0xFF;

                Log.Write(LogLevel.Client, "Received a packet [{0}]", Type.ToString());

                HandlePacket(inBuffer, Module, Type, Unk01, Client);
            }
            else
            {
                //Log.Write(LogLevel.Debug, "Received an encrypted packet");
                // Packet is encrypted
                byte[] decData = new byte[inBuffer.Length];

                Client.GetDecryptor().ProcessBytes(inBuffer, 0, inBuffer.Length, decData, 0);

                MemoryStream IStream = new MemoryStream(decData);
                EndianBinaryReader IReader = new EndianBinaryReader(MiscUtil.Conversion.BigEndianBitConverter.Little, IStream);

                int remLength = decData.Length;

                //Log.Write(LogLevel.Debug, "{0}", decData.ToHEX());


                do
                {
                    byte Module = IReader.ReadByte();
                    int pLength = IReader.ReadInt32();
                    int pChecksum = IReader.ReadByte();

                    if (VerifyChecksum(decData, pChecksum, (int)IReader.BaseStream.Position - 6))
                    {
                        //Log.Write(LogLevel.Client, "Length: {0}", pLength);

                        byte[] Data = Decompress(IReader.ReadBytes(pLength - 6), Client.GetInflateStream());

                        //Log.Write(LogLevel.Warning, "\n{0}", Data.ToHEX(Data.Length));

                        MemoryStream HStream = new MemoryStream(Data);
                        EndianBinaryReader HReader = new EndianBinaryReader(MiscUtil.Conversion.EndianBitConverter.Little, HStream);

                        PacketType Type;
                        UInt32 Unk01;
                        if (Module == 0x01) // Ping Packet
                            Type = PacketType.Ping;
                        else
                            Type = (PacketType)HReader.ReadUInt32();

                        Log.Write(LogLevel.Client, "Received a packet [{0}]", Type.ToString());

                        Unk01 = HReader.ReadUInt32();


                        HReader.Dispose();
                        HStream.Dispose();

                        HandlePacket(Data, Module, Type, Unk01, Client);
                    }

                    remLength -= pLength;
                }
                while (remLength > 0);
               
                IReader.Close();
                IStream.Close();
            }
        }
    }
}
