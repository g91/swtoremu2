using System;
using System.IO;
using System.Text;

namespace SWTORParser.Hero
{
    public class OmegaStream
    {
        public OmegaStream(Stream stream)
        {
            Stream = stream;
            ContentVersion = 0;
            TransportVersion = 0;
        }

        public Stream Stream { get; set; }

        public UInt16 ContentVersion { get; set; }

        public UInt16 TransportVersion { get; set; }

        public void CheckResourceHeader(UInt32 type, UInt16 minContentVersion, UInt16 maxContentVersion)
        {
            var buffer = new byte[8];
            Stream.Read(buffer, 0, 8);
            var num = BitConverter.ToUInt32(buffer, 0);
            ContentVersion = BitConverter.ToUInt16(buffer, 4);
            TransportVersion = BitConverter.ToUInt16(buffer, 6);

            if (num != type)
                throw new InvalidDataException("FOURCC value doesn't match");

            if (ContentVersion < minContentVersion)
                throw new InvalidDataException("Content format is too old, data can not be read");

            if (ContentVersion > maxContentVersion)
                throw new InvalidDataException(
                    "Content format saved with later version of software, data can not be read");

            if (TransportVersion < 1)
                throw new InvalidDataException("Transport format is too old, data can not be read");

            if (TransportVersion > 5)
                throw new InvalidDataException("Transport format saved with later version of software, data can not be read");
        }

        public UInt64 ReadULong()
        {
            var buffer = new Byte[8];
            Stream.Read(buffer, 0, 8);
            return BitConverter.ToUInt64(buffer, 0);
        }

        public UInt32 ReadUInt()
        {
            var buffer = new Byte[4];
            Stream.Read(buffer, 0, 4);
            return BitConverter.ToUInt32(buffer, 0);
        }

        public Int32 ReadInt()
        {
            var buffer = new byte[4];
            Stream.Read(buffer, 0, 4);
            return BitConverter.ToInt32(buffer, 0);
        }

        public String ReadString()
        {
            var count = ReadInt();
            var numArray = new Byte[count];
            Stream.Read(numArray, 0, count);
            return Encoding.ASCII.GetString(numArray, 0, count - 1);
        }

        public SByte ReadSByte()
        {
            return (SByte) Stream.ReadByte();
        }

        public UInt16 ReadUShort()
        {
            var buffer = new Byte[2];
            Stream.Read(buffer, 0, 2);
            return BitConverter.ToUInt16(buffer, 0);
        }

        public Byte[] ReadBytes(UInt32 length)
        {
            var buffer = new Byte[length];
            Stream.Read(buffer, 0, buffer.Length);
            return buffer;
        }

        public Byte[] ReadFrame()
        {
            var count = ReadInt();
            var buffer = new Byte[count];
            Stream.Read(buffer, 0, count);
            return buffer;
        }

        public Byte Peek()
        {
            var num = ReadByte();
            Stream.Seek(-1L, SeekOrigin.Current);
            return num;
        }

        public Byte ReadByte()
        {
            return (Byte) Stream.ReadByte();
        }

        public void WriteByte(Byte value)
        {
            Stream.WriteByte(value);
        }

        public void WriteBytes(Byte[] value)
        {
            Stream.Write(value, 0, value.Length);
        }
    }
}