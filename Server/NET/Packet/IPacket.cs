using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using MiscUtil.Conversion;
using System.Security.Cryptography;

namespace NexusToRServer.NET
{
    public abstract class IPacket
    {
        public byte[] _buffer;
        public MemoryStream _stream;
        private TORGameClient _client;

        public void SetClient(TORGameClient inClient)
        {
            _client = inClient;
        }

        public TORGameClient GetClient()
        {
            return _client;
        }

        public byte GenerateChecksum(byte[] inBuffer)
        {
            return (byte)(inBuffer[0] ^ inBuffer[1] ^ inBuffer[2] ^ inBuffer[3] ^ inBuffer[4]);
        }

        #region Packet Reader

        private EndianBinaryReader _reader;

        public abstract Boolean Read();
        public abstract void Run();

        protected Int16 ReadInt16()
        {
            return _reader.ReadInt16();
        }

        protected Int32 ReadInt32()
        {
            return _reader.ReadInt32();
        }

        protected Int64 ReadInt64()
        {
            return _reader.ReadInt64();
        }

        protected UInt16 ReadUInt16()
        {
            return _reader.ReadUInt16();
        }

        protected UInt32 ReadUInt32()
        {
            return _reader.ReadUInt32();
        }

        protected UInt64 ReadUInt64()
        {
            return _reader.ReadUInt64();
        }

        protected byte ReadByte()
        {
            return _reader.ReadByte();
        }

        protected Boolean ReadBoolean()
        {
            return _reader.ReadBoolean();
        }

        protected String ReadString()
        {
            UInt32 pLength = _reader.ReadUInt32();
            byte[] sData = _reader.ReadBytes((int)pLength);
            
            if (sData[sData.Length - 1] == 0x00)
                pLength--;

            return _reader.Encoding.GetString(sData, 0, (int)pLength);
        }

        protected byte[] ReadBytes(int count)
        {
            return _reader.ReadBytes(count);
        }

        protected float ReadFloat()
        {
            return _reader.ReadSingle();
        }

        public void SetBuffers(byte[] inBuffer)
        {
            _buffer = inBuffer;
            _stream = new MemoryStream(_buffer);
            _reader = new EndianBinaryReader(EndianBitConverter.Little, _stream);
        }

        public void Dispose()
        {
            _buffer = null;
            _stream.Dispose();
            _reader.Dispose();
        }

        #endregion
    }
}
