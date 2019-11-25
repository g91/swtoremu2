using System;
using System.IO;
using System.Text;

namespace Hero
{
  public class OmegaStream
  {
    public Stream Stream { get; set; }

    public ushort ContentVersion { get; set; }

    public ushort TransportVersion { get; set; }

    public OmegaStream(Stream stream)
    {
      this.Stream = stream;
      this.ContentVersion = (ushort) 0;
      this.TransportVersion = (ushort) 0;
    }

    public void CheckResourceHeader(uint type, ushort minContentVersion, ushort maxContentVersion)
    {
      byte[] buffer = new byte[8];
      this.Stream.Read(buffer, 0, 8);
      uint num = BitConverter.ToUInt32(buffer, 0);
      this.ContentVersion = BitConverter.ToUInt16(buffer, 4);
      this.TransportVersion = BitConverter.ToUInt16(buffer, 6);
      if ((int) num != (int) type)
        throw new InvalidDataException("FOURCC value doesn't match");
      if ((int) this.ContentVersion < (int) minContentVersion)
        throw new InvalidDataException("Content format is too old, data can not be read");
      if ((int) this.ContentVersion > (int) maxContentVersion)
        throw new InvalidDataException("Content format saved with later version of software, data can not be read");
    }

    public ulong ReadULong()
    {
      byte[] buffer = new byte[8];
      this.Stream.Read(buffer, 0, 8);
      return BitConverter.ToUInt64(buffer, 0);
    }

    public uint ReadUInt()
    {
      byte[] buffer = new byte[4];
      this.Stream.Read(buffer, 0, 4);
      return BitConverter.ToUInt32(buffer, 0);
    }

    public int ReadInt()
    {
      byte[] buffer = new byte[4];
      this.Stream.Read(buffer, 0, 4);
      return BitConverter.ToInt32(buffer, 0);
    }

    public string ReadString()
    {
      int count = this.ReadInt();
      byte[] numArray = new byte[count];
      this.Stream.Read(numArray, 0, count);
      return Encoding.ASCII.GetString(numArray, 0, count - 1);
    }

    public sbyte ReadSByte()
    {
      return (sbyte) this.Stream.ReadByte();
    }

    public ushort ReadUShort()
    {
      byte[] buffer = new byte[2];
      this.Stream.Read(buffer, 0, 2);
      return BitConverter.ToUInt16(buffer, 0);
    }

    public byte[] ReadBytes(uint length)
    {
      byte[] buffer = new byte[length];
      this.Stream.Read(buffer, 0, buffer.Length);
      return buffer;
    }

    public byte[] ReadFrame()
    {
      int count = this.ReadInt();
      byte[] buffer = new byte[count];
      this.Stream.Read(buffer, 0, count);
      return buffer;
    }

    public byte Peek()
    {
      byte num = this.ReadByte();
      this.Stream.Seek(-1L, SeekOrigin.Current);
      return num;
    }

    public byte ReadByte()
    {
      return (byte) this.Stream.ReadByte();
    }

    public void WriteByte(byte value)
    {
      this.Stream.WriteByte(value);
    }

    public void WriteBytes(byte[] value)
    {
      this.Stream.Write(value, 0, value.Length);
    }
  }
}
