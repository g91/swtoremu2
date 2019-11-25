using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using MiscUtil.Conversion;
using System.Security.Cryptography;

namespace NexusToRServer.NET
{
    public abstract class SPacket
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

        #region Packet Writer

        public abstract void Write();

        private EndianBinaryWriter _writer;

        protected void WriteInt16(Int16 value)
        {
            _writer.Write(value);
        }

        protected void WriteInt32(Int32 value)
        {
            _writer.Write(value);
        }

        protected void WriteInt64(Int64 value)
        {
            _writer.Write(value);
        }

        protected void WriteUInt16(UInt16 value)
        {
            _writer.Write(value);
        }

        protected void WriteUInt32(UInt32 value)
        {
            _writer.Write(value);
        }

        protected void WriteUInt64(UInt64 value)
        {
            _writer.Write(value);
        }

        protected void WriteByte(byte value)
        {
            _writer.Write(value);
        }

        protected void WriteBoolean(Boolean value)
        {
            _writer.Write(value);
        }

        protected void WriteString(string value, bool hasTerminator = true)
        {
            if (hasTerminator)
            {
                _writer.Write(value, true);
            }
            else
            {
                _writer.Write((Int32)value.Length);
                _writer.Write(_writer.Encoding.GetBytes(value));
            }
        }

        protected void WriteBytes(byte[] value)
        {
            _writer.Write(value, 0, value.Length);
        }

        protected void WriteBytes(byte[] value, int offset, int length)
        {
            _writer.Write(value, offset, length);
        }

        protected void WriteFloat(float value)
        {
            _writer.Write((Single)value);
        }

        public void InitBuffers()
        {
            _stream = new MemoryStream();
            _writer = new EndianBinaryWriter(EndianBitConverter.Little, _stream);
        }
        #endregion
    }
}
