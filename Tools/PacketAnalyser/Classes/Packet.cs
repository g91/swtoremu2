using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using ComponentAce.Compression.Libs.zlib;

namespace PacketAnalyser
{
    class PacketStream
    {
        public List<Packet> Packets;

        public byte[] Decompress(byte[] pBuffer, ZStream iStream)
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
                    break;
                }

                lStream.Write(oBuff, 0, (pBuffer.Length * 8) - iStream.avail_out);
            }
            while (iStream.avail_in != 0 || iStream.avail_out == 0);
            byte[] rBASD = lStream.ToArray();

            lStream.Dispose();

            return rBASD;
        }

        public bool VerifyChecksum(byte[] pBuffer, int pChecksum, int index = 0)
        {
            if ((byte)pChecksum == (pBuffer[index + 0] ^ pBuffer[index + 1] ^ pBuffer[index + 2] ^ pBuffer[index + 3] ^ pBuffer[index + 4]))
                return true;
            return false;
        }

        public PacketStream(List<byte[]> inPack, IStreamCipher Decryptor, ZStream Inflater)
        {
            Packets = new List<Packet>();

            byte[] inBuff = inPack[0];

            byte[] decData = new byte[inBuff.Length];

            Decryptor.ProcessBytes(inBuff, 0, inBuff.Length, decData, 0);

            MemoryStream IStream = new MemoryStream(decData);
            EndianBinaryReader IReader = new EndianBinaryReader(MiscUtil.Conversion.BigEndianBitConverter.Little, IStream);

            int remLength = decData.Length;

            do
            {
                byte Module = IReader.ReadByte();
                int pLength = IReader.ReadInt32();
                int pChecksum = IReader.ReadByte();

                if (VerifyChecksum(decData, pChecksum, (int)IReader.BaseStream.Position - 6))
                {
                    byte[] Data;

                    if (inPack.Count > 1)
                    {
                        // Multipart packet
                        byte[] NewBuff = new byte[pLength - 6];
                        int curIndex = remLength - 6;
                        Array.Copy(IReader.ReadBytes(remLength - 6), 0, NewBuff, 0, remLength - 6);
                        for (int i = 1; i < inPack.Count; i++)
                        {
                            byte[] packDec = new byte[inPack[i].Length];
                            Decryptor.ProcessBytes(inPack[i], 0, inPack[i].Length, packDec, 0);
                            Array.Copy(packDec, 0, NewBuff, curIndex, packDec.Length);
                            curIndex += packDec.Length;
                        }
                        Data = NewBuff;
                    }
                    else
                    {
                        Data = IReader.ReadBytes(pLength - 6);
                    }

                    Packet iPacket = new Packet();
                    iPacket.Module = Module;
                    iPacket.Data = Decompress(Data, Inflater);

                    iPacket.Stream = new MemoryStream(iPacket.Data);
                    iPacket.Reader = new EndianBinaryReader(MiscUtil.Conversion.EndianBitConverter.Little, iPacket.Stream);

                    iPacket.PacketID = iPacket.Reader.ReadUInt32();

                    //if (iPacket.PacketID == 0x34287945)
                    // Console.WriteLine(decData.ToHEX());

                    iPacket.Reader.ReadUInt32();

                    //iPacket.IsValid = true;

                    Packets.Add(iPacket);
                }
                else
                {
                    Console.WriteLine("Failure!!!!", inBuff.ToHEX(), decData.ToHEX());
                    break;
                }

                remLength -= pLength;

            }
            while (remLength > 0);

            IReader.Close();
            IStream.Close();
        }

        public PacketStream(byte[] inBuff)
        {
            Packets = new List<Packet>();

            MemoryStream Stream = new MemoryStream(inBuff);
            EndianBinaryReader Reader = new EndianBinaryReader(MiscUtil.Conversion.BigEndianBitConverter.Little, Stream);

            int remLength = inBuff.Length;

            do
            {
                Packet iPacket = new Packet();

                iPacket.Module = Reader.ReadByte();
                int pLength = Reader.ReadInt32();
                int pChecksum = Reader.ReadByte();

                try
                {
                    if (iPacket.VerifyChecksum(inBuff, pChecksum, (int)Reader.BaseStream.Position - 6))
                    {
                        byte[] Data = Reader.ReadBytes(pLength - 6);

                        if (Data.Length >= 4)
                        {
                            iPacket.Stream = new MemoryStream(Data);
                            iPacket.Reader = new EndianBinaryReader(MiscUtil.Conversion.EndianBitConverter.Little, iPacket.Stream);

                            iPacket.PacketID = iPacket.Reader.ReadUInt32();

                            iPacket.Reader.ReadUInt32();

                            iPacket.IsValid = true;

                            byte[] cData = new byte[pLength];
                            Array.Copy(inBuff, 0, cData, 0, pLength);

                            iPacket.Data = Data;
                            iPacket.cData = cData;

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

            Reader.Close();
            Stream.Close();
        }
    }

    class Packet
    {
        public byte[] RSAData;
        public MemoryStream Stream;
        public EndianBinaryReader Reader;
        public EndianBinaryWriter Writer;
        public UInt32 PacketID;
        public byte Module;
        public UInt32 Unk01;

        public byte[] cData;
        public byte[] Data;
        public bool IsValid;

        public Packet()
        {
            Data = new byte[] { };
            cData = new byte[] { };
        }

        public Packet(UInt32 inType, UInt32 Component, byte Module)
        {
            this.Module = Module;
            this.Stream = new MemoryStream();
            this.Writer = new EndianBinaryWriter(MiscUtil.Conversion.EndianBitConverter.Little, this.Stream);

            this.PacketID = inType;

            this.Writer.Write((UInt32)inType);
            this.Writer.Write(Component); // TODO
        }

        public string GetPacketStr()
        {
            return String.Format("[0x{0:X8}] (0x{1:X2})", this.PacketID, this.Module);
        }

        public bool VerifyChecksum(byte[] pBuffer, int pChecksum, int index = 0)
        {
            if ((byte)pChecksum == (pBuffer[index + 0] ^ pBuffer[index + 1] ^ pBuffer[index + 2] ^ pBuffer[index + 3] ^ pBuffer[index + 4]))
                return true;
            return false;
        }
    }
}