using System;
using System.Text;

namespace Hero
{
  public class Frame
  {
    protected byte[] buffer;
    protected int readPosition;
    protected int writePosition;

    public int ReadPosition
    {
      get
      {
        return this.readPosition;
      }
    }

    public Frame()
    {
      this.buffer = (byte[]) null;
      this.readPosition = 0;
      this.writePosition = 0;
    }

    public Frame(byte[] data)
    {
      this.buffer = data;
      this.readPosition = 0;
      this.writePosition = this.buffer.Length;
    }

    public void SeekToBegin()
    {
      this.readPosition = 0;
    }

    public int GetAvailForRead()
    {
      return this.writePosition - this.readPosition;
    }

    public int GetAvailForWrite()
    {
      if (this.buffer == null)
        return 0;
      else
        return this.buffer.Length - this.writePosition;
    }

    public int GetSize()
    {
      return this.writePosition;
    }

    public byte[] GetBuffer()
    {
      return this.buffer;
    }

    public void CheckSize(int length)
    {
      if (this.buffer == null)
      {
        this.buffer = new byte[length];
      }
      else
      {
        if (this.GetAvailForWrite() >= length)
          return;
        byte[] numArray = new byte[this.buffer.Length + length];
        Array.Copy((Array) this.buffer, (Array) numArray, this.buffer.Length);
        this.buffer = numArray;
      }
    }

    public void Write(bool value)
    {
      this.CheckSize(1);
      this.buffer[this.writePosition] = value ? (byte) 1 : (byte) 0;
      ++this.writePosition;
    }

    public void Write(sbyte value)
    {
      this.CheckSize(1);
      this.buffer[this.writePosition] = (byte) value;
      ++this.writePosition;
    }

    public void Write(byte value)
    {
      this.CheckSize(1);
      this.buffer[this.writePosition] = value;
      ++this.writePosition;
    }

    public void Write(short value)
    {
      this.Write(BitConverter.GetBytes(value));
    }

    public void Write(ushort value)
    {
      this.Write(BitConverter.GetBytes(value));
    }

    public void Write(int value)
    {
      this.Write(BitConverter.GetBytes(value));
    }

    public void Write(uint value)
    {
      this.Write(BitConverter.GetBytes(value));
    }

    public void Write(long value)
    {
      this.Write(BitConverter.GetBytes(value));
    }

    public void Write(ulong value)
    {
      this.Write(BitConverter.GetBytes(value));
    }

    public void Write(float value)
    {
      this.Write(BitConverter.GetBytes(value));
    }

    public void Write(double value)
    {
      this.Write(BitConverter.GetBytes(value));
    }

    public void Write(string value)
    {
      if (value == null)
        value = "";
      byte[] bytes = Encoding.ASCII.GetBytes(value);
      this.Write(bytes.Length + 1);
      this.Write(bytes);
      this.Write((byte) 0);
    }

    public void Write(byte[] data)
    {
      this.Write(data, 0, data.Length);
    }

    public void Write(byte[] data, int offset, int length)
    {
      this.CheckSize(length);
      Array.Copy((Array) data, offset, (Array) this.buffer, this.writePosition, length);
      this.writePosition += length;
    }

    public void Write(uint[] data)
    {
      uint num = (uint) data.Length;
      this.Write(num);
      for (uint index = 0U; index < num; ++index)
        this.Write(data[index]);
    }

    public void Write(ulong[] data)
    {
      uint num = (uint) data.Length;
      this.Write(num);
      for (uint index = 0U; index < num; ++index)
        this.Write(data[index]);
    }

    public void WriteData(byte[] data)
    {
      if (data == null)
      {
        this.Write(0);
      }
      else
      {
        int length = data.Length;
        this.CheckSize(length + 4);
        this.Write(length);
        Array.Copy((Array) data, 0, (Array) this.buffer, this.writePosition, length);
        this.writePosition += length;
      }
    }

    public bool ReadBool()
    {
      if (this.GetAvailForRead() < 1)
        throw new Frame.EndOfBufferException();
      bool flag = BitConverter.ToBoolean(this.buffer, this.readPosition);
      ++this.readPosition;
      return flag;
    }

    public byte ReadByte()
    {
      if (this.GetAvailForRead() < 1)
        throw new Frame.EndOfBufferException();
      byte num = this.buffer[this.readPosition];
      ++this.readPosition;
      return num;
    }

    public sbyte ReadSByte()
    {
      if (this.GetAvailForRead() < 1)
        throw new Frame.EndOfBufferException();
      sbyte num = (sbyte) this.buffer[this.readPosition];
      ++this.readPosition;
      return num;
    }

    public short ReadShort()
    {
      if (this.GetAvailForRead() < 2)
        throw new Frame.EndOfBufferException();
      short num = BitConverter.ToInt16(this.buffer, this.readPosition);
      this.readPosition += 2;
      return num;
    }

    public ushort ReadUShort()
    {
      if (this.GetAvailForRead() < 2)
        throw new Frame.EndOfBufferException();
      ushort num = BitConverter.ToUInt16(this.buffer, this.readPosition);
      this.readPosition += 2;
      return num;
    }

    public int ReadInt()
    {
      if (this.GetAvailForRead() < 4)
        throw new Frame.EndOfBufferException();
      int num = BitConverter.ToInt32(this.buffer, this.readPosition);
      this.readPosition += 4;
      return num;
    }

    public uint ReadUInt()
    {
      if (this.GetAvailForRead() < 4)
        throw new Frame.EndOfBufferException();
      uint num = BitConverter.ToUInt32(this.buffer, this.readPosition);
      this.readPosition += 4;
      return num;
    }

    public long ReadLong()
    {
      if (this.GetAvailForRead() < 8)
        throw new Frame.EndOfBufferException();
      long num = BitConverter.ToInt64(this.buffer, this.readPosition);
      this.readPosition += 8;
      return num;
    }

    public ulong ReadULong()
    {
      if (this.GetAvailForRead() < 8)
        throw new Frame.EndOfBufferException();
      ulong num = BitConverter.ToUInt64(this.buffer, this.readPosition);
      this.readPosition += 8;
      return num;
    }

    public float ReadFloat()
    {
      if (this.GetAvailForRead() < 4)
        throw new Frame.EndOfBufferException();
      float num = BitConverter.ToSingle(this.buffer, this.readPosition);
      this.readPosition += 4;
      return num;
    }

    public double ReadDouble()
    {
      if (this.GetAvailForRead() < 8)
        throw new Frame.EndOfBufferException();
      double num = BitConverter.ToDouble(this.buffer, this.readPosition);
      this.readPosition += 8;
      return num;
    }

    public string ReadString()
    {
      int num = this.ReadInt();
      if (this.GetAvailForRead() < num)
        throw new Frame.EndOfBufferException();
      string @string = Encoding.ASCII.GetString(this.buffer, this.readPosition, num - 1);
      this.readPosition += num;
      return @string;
    }

    public byte[] ReadBytes(int length)
    {
      if (this.GetAvailForRead() < length)
        throw new Frame.EndOfBufferException();
      byte[] numArray = new byte[length];
      Array.Copy((Array) this.buffer, this.readPosition, (Array) numArray, 0, length);
      this.readPosition += length;
      return numArray;
    }

    public void ReadBytes(byte[] value)
    {
      this.ReadBytes(value, 0, value.Length);
    }

    public void ReadBytes(byte[] value, int length)
    {
      this.ReadBytes(value, 0, length);
    }

    public void ReadBytes(byte[] value, int offset, int length)
    {
      if (this.GetAvailForRead() < length)
        throw new Frame.EndOfBufferException();
      Array.Copy((Array) this.buffer, this.readPosition, (Array) value, offset, length);
      this.readPosition += length;
    }

    public byte[] ReadData()
    {
      uint num = this.ReadUInt();
      if ((long) this.GetAvailForRead() < (long) num)
        throw new Frame.EndOfBufferException();
      byte[] numArray = new byte[num];
      Array.Copy((Array) this.buffer, (long) this.readPosition, (Array) numArray, 0L, (long) num);
      this.readPosition += (int) num;
      return numArray;
    }

    public uint[] ReadArrayUInt()
    {
      uint num = this.ReadUInt();
      uint[] numArray = new uint[num];
      for (uint index = 0U; index < num; ++index)
        numArray[index] = this.ReadUInt();
      return numArray;
    }

    public ulong[] ReadArrayULong()
    {
      uint num = this.ReadUInt();
      ulong[] numArray = new ulong[num];
      for (uint index = 0U; index < num; ++index)
        numArray[index] = this.ReadULong();
      return numArray;
    }

    public void Empty()
    {
      this.buffer = (byte[]) null;
      this.readPosition = 0;
      this.writePosition = 0;
    }

    public class EndOfBufferException : Exception
    {
      public EndOfBufferException()
        : base("End of buffer reached.")
      {
      }
    }
  }
}
