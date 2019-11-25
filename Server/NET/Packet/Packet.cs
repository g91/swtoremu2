using System;
using System.IO;
using System.Security.Cryptography;
using ComponentAce.Compression.Libs.zlib;

namespace NexusToRServer
{
    class Packet
    {
        public byte[] RSAData;
        public MemoryStream Stream;
        public EndianBinaryReader Reader;
        public EndianBinaryWriter Writer;
        public CPacketType PacketID;
        public byte Module;
        public UInt32 Unk01;

        public byte[] Data;
        public bool IsValid;

        public Packet()
        {
        }

        public Packet(CPacketType inType, UInt32 Component, byte Module)
        {
            this.Module = Module;
            this.Stream = new MemoryStream();
            this.Writer = new EndianBinaryWriter(MiscUtil.Conversion.EndianBitConverter.Little, this.Stream);

            this.PacketID = inType;

            this.Writer.Write((UInt32)inType);
            this.Writer.Write(Component); // TODO
        }

        public void Construct(ZStream dStream)
        {
            Log.Write(LogLevel.Client, "Constructing Packet [{0}]", this.PacketID.ToString());
            
            // Compress buffer
            byte[] cData = this.Stream.ToArray();

            MemoryStream lStream = new MemoryStream();

            dStream.avail_in = cData.Length;
            dStream.next_in = cData;
            dStream.next_in_index = 0;

            byte[] dData = new byte[cData.Length * 2];

            dStream.avail_out = cData.Length * 2;
            dStream.next_out = dData;
            dStream.next_out_index = 0;

            dStream.deflate(2);

            lStream.Write(dData, 0, (cData.Length * 2) - dStream.avail_out);
            cData = lStream.ToArray();
            lStream.Dispose();

            //Log.Write(LogLevel.Error, "SHIEEEEEEEEEE\n{0}", cData.ToHEX(cData.Length));
            

            MemoryStream oStream = new MemoryStream();
            EndianBinaryWriter oWriter = new EndianBinaryWriter(MiscUtil.Conversion.EndianBitConverter.Little, oStream);

            oWriter.Write((byte)this.Module);
            oWriter.Write((UInt32)cData.Length + 2);
            oWriter.Write((byte)GenerateChecksum(oStream.ToArray()));
            oWriter.Write(cData, 0, cData.Length - 4);

            this.Data = oStream.ToArray();
        }

        public byte[] Finalize()
        {
            return Data;
        }

        public byte[] Finalize(IStreamCipher pEncryptor)
        {
            //Log.Write(LogLevel.Warning, "\n{0}", this.Data.ToHEX(this.Data.Length));
            byte[] oData = new byte[Data.Length];
            pEncryptor.ProcessBytes(Data, 0, Data.Length, oData, 0);
            return oData;
        }
        
        private byte GenerateChecksum(byte[] inBuffer)
        {
            return (byte)(inBuffer[0] ^ inBuffer[1] ^ inBuffer[2] ^ inBuffer[3] ^ inBuffer[4]);
        }

        public bool VerifyChecksum(byte[] pBuffer, int pChecksum, int index = 0)
        {
            if ((byte)pChecksum == (pBuffer[index + 0] ^ pBuffer[index + 1] ^ pBuffer[index + 2] ^ pBuffer[index + 3] ^ pBuffer[index + 4]))
                return true;
            return false;
        }
    }
}
