using System;
using System.Collections.Generic;
using System.IO;

namespace SWTORParser.Classes
{
    public class PacketStream
    {
        public List<Packet> Packets;
        public Boolean FromServer { get; set; }

        private byte[] Decompress(Byte[] pBuffer)
        {
            var lStream = new MemoryStream();

            var rBasd = lStream.ToArray();

            Console.WriteLine("Decrypted!");

            return rBasd;
            /*
            try
            {
                dStream.Write(rBuff, 0, rBuff.Length);
            }
            catch
            {
                Console.WriteLine("Zlib Failed: {0}", rBuff.ToHEX());
                //Console.ReadLine();
            }
            dStream.Flush();

            byte[] finalBuff = iStream.ToArray();

            iStream.SetLength(0);
            iStream.Position = 0;

            return finalBuff;*/
        }

        public PacketStream(Byte[] inBuff, Boolean fromServer)
        {
            FromServer = fromServer;
            Packets = new List<Packet>();

            var stream = new MemoryStream(inBuff);
            var reader = new EndianBinaryReader(MiscUtil.Conversion.EndianBitConverter.Little, stream);

            var remLength = inBuff.Length;

            do
            {
                var iPacket = new Packet
                {
                    Module = reader.ReadByte(),
                    FromServer = FromServer
                };

                var pLength = reader.ReadInt32();
                var pChecksum = reader.ReadByte();

                try
                {
                    if (iPacket.VerifyChecksum(inBuff, pChecksum, (int)reader.BaseStream.Position - 6))
                    {
                        var data = reader.ReadBytes(pLength - 6);

                        if (data.Length >= 4)
                        {
                            iPacket.Stream = new MemoryStream(data);
                            iPacket.Reader = new EndianBinaryReader(MiscUtil.Conversion.EndianBitConverter.Little, iPacket.Stream);

                            iPacket.PacketID = iPacket.Reader.ReadUInt32();

                            iPacket.ContentVersion = iPacket.Reader.ReadUInt16();
                            iPacket.TransportVersion = iPacket.Reader.ReadUInt16();

                            iPacket.IsValid = true;

                            var cData = new Byte[pLength];
                            Array.Copy(inBuff, 0, cData, 0, pLength);

                            iPacket.Data = data;
                            iPacket.CData = cData;

                            Packets.Add(iPacket);
                        }
                    }
                    else
                        return;
                }
                catch { }

                remLength -= pLength;
            }
            while (remLength > 0);

            reader.Close();
            stream.Close();
        }
    }

    public class Packet
    {
        public Byte[] RsaData;
        public MemoryStream Stream;
        public EndianBinaryReader Reader;
        public EndianBinaryWriter Writer;
        public UInt32 PacketID;
        public byte Module;
        public UInt32 Unk01;

        public Byte[] CData;
        public Byte[] Data;
        public Boolean IsValid;

        public UInt16 TransportVersion;
        public UInt16 ContentVersion;

        public Boolean FromServer { get; set; }

        public Packet()
        {
            Data = new Byte[] { };
            CData = new Byte[] { };
        }

        public Packet(UInt32 inType, UInt32 component, byte module)
        {
            Module = module;
            Stream = new MemoryStream();
            Writer = new EndianBinaryWriter(MiscUtil.Conversion.EndianBitConverter.Little, Stream);

            PacketID = inType;

            Writer.Write(inType);
            Writer.Write(component); // TODO
        }

        public String GetPacketStr()
        {
            return String.Format("[0x{0:X8}] (0x{1:X2})", PacketID, Module);
        }

        public Boolean VerifyChecksum(Byte[] pBuffer, Int32 pChecksum, Int32 index = 0)
        {
            return (Byte)pChecksum == (pBuffer[index + 0] ^ pBuffer[index + 1] ^ pBuffer[index + 2] ^ pBuffer[index + 3] ^ pBuffer[index + 4]);
        }
    }
}