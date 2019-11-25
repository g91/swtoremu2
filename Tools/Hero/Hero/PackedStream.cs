using System;
using System.IO;
using System.Text;

namespace Hero
{
  public class PackedStream : OmegaStream
  {
    public bool[] Flags;

    public int Style { get; set; }

    public PackedStream(int style, Stream stream)
      : base(stream)
    {
      this.Style = style;
      this.Flags = new bool[6];
      switch (style)
      {
        case 0:
          break;
        case 1:
          this.Flags[0] = true;
          this.Flags[2] = true;
          this.Flags[3] = true;
          break;
        case 2:
          this.Flags[1] = true;
          this.Flags[0] = true;
          this.Flags[2] = true;
          this.Flags[3] = true;
          break;
        case 3:
          this.Flags[1] = true;
          this.Flags[0] = true;
          this.Flags[5] = true;
          this.Flags[2] = true;
          this.Flags[3] = true;
          break;
        case 4:
          this.Flags[0] = true;
          this.Flags[5] = true;
          this.Flags[2] = true;
          this.Flags[3] = true;
          break;
        case 5:
          this.Flags[3] = true;
          this.Flags[0] = true;
          break;
        case 6:
          this.Flags[1] = true;
          this.Flags[3] = true;
          break;
        case 7:
        case 8:
          this.Flags[2] = true;
          this.Flags[4] = true;
          this.Flags[5] = true;
          break;
        case 9:
        case 10:
          this.Flags[5] = true;
          this.Flags[2] = true;
          this.Flags[0] = true;
          break;
        default:
          throw new InvalidDataException("Invalid stream style");
      }
    }

    public void Read(out ulong value)
    {
      byte num1 = (byte) this.Stream.ReadByte();
      value = 0UL;
      if ((int) this.TransportVersion > 1)
      {
        if ((int) num1 >= 192)
        {
          if ((int) num1 < 200 || (int) num1 > 207)
            throw new SerializingException("Invalid token in stream");
          byte num2 = (byte) ((uint) num1 - 199U);
          this.ReadPacked(out value, (int) num2);
        }
        else
          value = (ulong) num1;
      }
      else if ((int) num1 >= 128)
      {
        if ((int) num1 < 176 || (int) num1 > 191)
          throw new SerializingException("Invalid token in stream");
        byte num2 = (byte) ((uint) num1 - 175U);
        this.ReadPacked(out value, (int) num2);
      }
      else
        value = (ulong) num1;
    }

    protected int BytesNeeded(ulong value)
    {
      for (int index = 7; index >= 0; --index)
      {
        if (((long) value & (long) byte.MaxValue << index * 8) != 0L)
          return index + 1;
      }
      return 0;
    }

    public void Write(ulong value)
    {
      if ((int) this.TransportVersion > 1)
      {
        if (value < 192UL)
        {
          this.WriteByte((byte) value);
        }
        else
        {
          int length = this.BytesNeeded(value);
          this.WriteByte((byte) (199 + length));
          this.WritePacked(value, length);
        }
      }
      else if (value < 128UL)
      {
        this.WriteByte((byte) value);
      }
      else
      {
        int length = this.BytesNeeded(value);
        this.WriteByte((byte) (175 + length));
        this.WritePacked(value, length);
      }
    }

    protected void ReadPacked(out ulong value, int length)
    {
      value = 0UL;
      if (length > 8)
        return;
      byte[] numArray = this.ReadBytes((uint) length);
      for (byte index = (byte) 0; (int) index < length; ++index)
        value = value << 8 | (ulong) numArray[(int) index];
    }

    protected void WritePacked(ulong value, int length)
    {
      byte[] numArray = new byte[length];
      byte[] bytes = BitConverter.GetBytes(value);
      for (int index = 0; index < length; ++index)
        numArray[index] = bytes[length - index - 1];
      this.WriteBytes(numArray);
    }

    public void Read(out uint a, out uint b)
    {
      ulong num = 0UL;
      if (this.Flags[3])
      {
        this.Read(out num);
        a = (uint) num;
        this.Read(out num);
        b = (uint) num;
      }
      else
      {
        this.Read(out num);
        a = (uint) num;
        b = (uint) num;
      }
    }

    public void Write(int a, int b)
    {
      if (this.Flags[3])
      {
        this.Write((ulong) a);
        this.Write((ulong) b);
      }
      else
      {
        if (a != b)
          throw new SerializingException("counters must be equal for this stream type");
        this.Write((ulong) a);
      }
    }

    public void Read(out bool value)
    {
      value = false;
      byte num = this.ReadByte();
      if ((int) this.TransportVersion > 1)
      {
        if ((int) num == 0)
        {
          value = false;
        }
        else
        {
          if ((int) num != 1)
            throw new SerializingException("Invalid value for bool");
          value = true;
        }
      }
      else if ((int) num == 128)
      {
        value = false;
      }
      else
      {
        if ((int) num != 129)
          throw new SerializingException("Invalid token in stream");
        value = true;
      }
    }

    public void Write(bool value)
    {
      if ((int) this.TransportVersion > 1)
      {
        if (!value)
        {
          this.WriteByte((byte) 0);
        }
        else
        {
          if (!value)
            return;
          this.WriteByte((byte) 1);
        }
      }
      else if (!value)
      {
        this.WriteByte((byte)128);
      }
      else
      {
        if (!value)
          return;
        this.WriteByte((byte)129);
      }
    }

    public void Read(out float value)
    {
      value = 0.0f;
      if ((int) this.TransportVersion > 1)
      {
        value = BitConverter.ToSingle(BitConverter.GetBytes(this.ReadUInt()), 0);
      }
      else
      {
        if ((int) this.ReadByte() != 130)
          throw new SerializingException("Invalid token in stream");
        value = BitConverter.ToSingle(BitConverter.GetBytes(this.ReadUInt()), 0);
      }
    }

    public void Write(float value)
    {
      if ((int) this.TransportVersion > 1)
      {
        this.WriteBytes(BitConverter.GetBytes(value));
      }
      else
      {
        this.WriteByte((byte) 130);
        this.WriteBytes(BitConverter.GetBytes(value));
      }
    }

    public void Read(out byte[] data)
    {
      data = (byte[]) null;
      if ((int) this.TransportVersion <= 1 && (int) this.ReadByte() != 133)
        throw new SerializingException("Invalid token in stream");
      ulong num;
      this.Read(out num);
      data = this.ReadBytes((uint) num);
    }

    public void Write(byte[] data)
    {
      if ((int) this.TransportVersion <= 1)
        this.WriteByte((byte) 133);
      this.Write((ulong) data.Length);
      this.WriteBytes(data);
    }

    public void Read(out string str)
    {
      str = "";
      if ((int) this.TransportVersion <= 1 && (int) this.ReadByte() != 137)
        throw new SerializingException("Invalid token in stream");
      ulong num;
      this.Read(out num);
      if ((long) num == 0L)
        return;
      str = Encoding.ASCII.GetString(this.ReadBytes((uint) num));
    }

    public void Write(string str)
    {
      if ((int) this.TransportVersion <= 1)
        this.WriteByte((byte) 137);
      if (str == null || str.Length == 0)
      {
        this.Write(0UL);
      }
      else
      {
        byte[] bytes = Encoding.ASCII.GetBytes(str);
        this.Write((ulong) bytes.Length);
        this.WriteBytes(bytes);
      }
    }

    public void ReadVersion(out ulong value)
    {
      value = 0UL;
      byte num = this.ReadByte();
      if ((int) this.TransportVersion > 1)
      {
        if ((int) num != 209)
          throw new SerializingException("Invalid token in stream");
      }
      else if ((int) num != 254)
        throw new SerializingException("Invalid token in stream");
      this.Read(out value);
    }

    public void WriteVersion(ulong value)
    {
      if ((int) this.TransportVersion > 1)
        this.WriteByte((byte) 209);
      else
        this.WriteByte((byte) 254);
      this.Write(value);
    }

    public void CheckEnd()
    {
      byte num = this.ReadByte();
      if ((int) this.TransportVersion > 1)
      {
        if ((int) num != 211)
          throw new SerializingException("Invalid token in stream");
      }
      else if ((int) num != (int) byte.MaxValue)
        throw new SerializingException("Invalid token in stream");
    }

    public void WriteEnd()
    {
      if ((int) this.TransportVersion > 1)
        this.WriteByte((byte) 211);
      else
        this.WriteByte(byte.MaxValue);
    }

    public void Read(out long value)
    {
      value = 0L;
      if ((int) this.TransportVersion > 1)
      {
        byte num1 = this.ReadByte();
        if ((int) num1 < 192)
          value = (long) num1;
        else if ((int) (byte) ((uint) num1 + 56U) > 7)
        {
          if ((int) (byte) ((uint) num1 + 64U) > 7)
          {
            if ((int) num1 != 208)
              throw new SerializingException("Invalid token in stream");
            value = long.MinValue;
          }
          byte num2 = (byte) ((uint) num1 - 191U);
          ulong num3;
          this.ReadPacked(out num3, (int) num2);
          value = -(long) num3;
        }
        else
        {
          byte num2 = (byte) ((uint) num1 - 199U);
          ulong num3;
          this.ReadPacked(out num3, (int) num2);
          value = (long) num3;
        }
      }
      else
      {
        byte num1 = this.ReadByte();
        if ((int) num1 < 128)
          value = (long) num1;
        else if ((int) (byte) ((uint) num1 + 96U) > 15)
        {
          if ((int) (byte) ((uint) num1 + 112U) > 15)
          {
            if ((int) num1 != 143)
              throw new SerializingException("Invalid token in stream");
            value = long.MinValue;
          }
          byte num2 = (byte) ((uint) num1 - 143U);
          ulong num3;
          this.ReadPacked(out num3, (int) num2);
          value = -(long) num3;
        }
        else
        {
          byte num2 = (byte) ((uint) num1 - 159U);
          ulong num3;
          this.ReadPacked(out num3, (int) num2);
          value = (long) num3;
        }
      }
    }

    public void Write(long value)
    {
      if ((int) this.TransportVersion > 1)
      {
        if (value >= 0L && value < 192L)
          this.WriteByte((byte) value);
        else if (value >= 192L)
        {
          ulong num = (ulong) value;
          int length = this.BytesNeeded(num);
          this.WriteByte((byte) (199 + length));
          this.WritePacked(num, length);
        }
        else if (value == long.MinValue)
        {
          this.WriteByte((byte) 208);
        }
        else
        {
          ulong num = (ulong) -value;
          int length = this.BytesNeeded(num);
          this.WriteByte((byte) (191 + length));
          this.WritePacked(num, length);
        }
      }
      else if (value >= 0L && value < 128L)
        this.WriteByte((byte) value);
      else if (value >= 128L)
      {
        ulong num = (ulong) value;
        int length = this.BytesNeeded(num);
        this.WriteByte((byte) (159 + length));
        this.WritePacked(num, length);
      }
      else if (value == long.MinValue)
      {
        this.WriteByte((byte) 143);
      }
      else
      {
        ulong num = (ulong) -value;
        int length = this.BytesNeeded(num);
        this.WriteByte((byte) (143 + length));
        this.WritePacked(num, length);
      }
    }
  }
}
