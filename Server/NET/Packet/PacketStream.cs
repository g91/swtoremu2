using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;
using ComponentAce.Compression.Libs.zlib;

namespace NexusToRServer
{
    class PacketStream
    {
        public List<Packet> Packets;

        private byte[] Decompress(byte[] pBuffer, ZStream iStream)
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

            byte[] oBuff = new byte[pBuffer.Length * 8];

            iStream.next_out = oBuff;
            iStream.next_out_index = 0;
            iStream.avail_out = pBuffer.Length * 8;

            iStream.inflate(2);

            lStream.Write(oBuff, 0, (pBuffer.Length * 8) - iStream.avail_out);

            byte[] rBASD = lStream.ToArray();

            lStream.Dispose();

            return rBASD;
        }

        public PacketStream(byte[] mpBuffer, int mpLength, IStreamCipher mpDecryptor, ZStream iStream, bool IsHandshake = false)
        {
            Packets = new List<Packet>();
            if (IsHandshake)
            {
                MemoryStream Stream = new MemoryStream(mpBuffer);
                EndianBinaryReader Reader = new EndianBinaryReader(MiscUtil.Conversion.BigEndianBitConverter.Little, Stream);

                Reader.ReadByte();
                int Length = Reader.ReadInt32();
                Reader.ReadBytes(5);

                byte[] Data = Reader.ReadBytes(Length - 10);
                string RSAStr = Encoding.ASCII.GetString(Data);

                Packet iPacket = new Packet();

                iPacket.RSAData = new byte[RSAStr.Length / 2];
                for (int i = 0; i < RSAStr.Length; i += 2)
                    iPacket.RSAData[i / 2] = byte.Parse(RSAStr.Substring(i, 2), NumberStyles.HexNumber);

                Reader.Close();
                Stream.Close();

                Packets.Add(iPacket);
            }
            else
            {
                Packets = new List<Packet>();

                byte[] dBuffer = new byte[mpLength];
                mpDecryptor.ProcessBytes(mpBuffer, 0, mpLength, dBuffer, 0);

                MemoryStream Stream = new MemoryStream(dBuffer);
                EndianBinaryReader Reader = new EndianBinaryReader(MiscUtil.Conversion.BigEndianBitConverter.Little, Stream);

                int remLength = mpLength;

                do
                {
                    Packet iPacket = new Packet();

                    iPacket.Module = Reader.ReadByte();
                    int pLength = Reader.ReadInt32();
                    int pChecksum = Reader.ReadByte();

                    try
                    {
                        if (iPacket.VerifyChecksum(dBuffer, pChecksum, (int)Reader.BaseStream.Position - 6))
                        {
                            byte[] iData = Reader.ReadBytes(pLength - 6);
                            //Console.WriteLine("#########################################\n{0}", iData.ToHEX());
                            byte[] Data = Decompress(iData, iStream);

                            if (Data.Length >= 4)
                            {
                                iPacket.Stream = new MemoryStream(Data);
                                iPacket.Reader = new EndianBinaryReader(MiscUtil.Conversion.EndianBitConverter.Little, iPacket.Stream);

                                iPacket.PacketID = (CPacketType)iPacket.Reader.ReadUInt32();

                                iPacket.Reader.ReadUInt32();

                                iPacket.IsValid = true;

                                byte[] cData = new byte[pLength];
                                Array.Copy(dBuffer, 0, cData, 0, pLength);

                                iPacket.Data = Data;

                                Packets.Add(iPacket);
                            }
                        }
                    }
                    catch { }

                    remLength -= pLength;
                }
                while (remLength > 0);

                Reader.Close();
                Stream.Close();
            }
        }
    }

}
