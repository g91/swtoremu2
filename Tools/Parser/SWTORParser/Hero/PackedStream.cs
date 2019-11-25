using System;
using System.IO;
using System.Text;

namespace SWTORParser.Hero
{
    public class PackedStream : OmegaStream
    {
        public bool[] Flags;

        public PackedStream(Int32 style, Stream stream)
            : base(stream)
        {
            Style = style;
            Flags = new Boolean[6];

            switch (style)
            {
                case 0:
                    break;

                case 1:
                    Flags[0] = true;
                    Flags[2] = true;
                    Flags[3] = true;
                    break;

                case 2:
                    Flags[1] = true;
                    Flags[0] = true;
                    Flags[2] = true;
                    Flags[3] = true;
                    break;

                case 3:
                    Flags[1] = true;
                    Flags[0] = true;
                    Flags[5] = true;
                    Flags[2] = true;
                    Flags[3] = true;
                    break;

                case 4:
                    Flags[0] = true;
                    Flags[5] = true;
                    Flags[2] = true;
                    Flags[3] = true;
                    break;

                case 5:
                    Flags[3] = true;
                    Flags[0] = true;
                    break;

                case 6:
                    Flags[1] = true;
                    Flags[3] = true;
                    break;

                case 7:
                case 8:
                    Flags[2] = true;
                    Flags[4] = true;
                    Flags[5] = true;
                    break;

                case 9:
                case 10:
                    Flags[5] = true;
                    Flags[2] = true;
                    Flags[0] = true;
                    break;

                default:
                    throw new InvalidDataException("Invalid stream style");
            }
        }

        public int Style { get; set; }

        public void Read(out UInt64 value)
        {
            var num1 = (Byte) Stream.ReadByte();
            value = 0UL;
            if (TransportVersion > 1)
            {
                if (num1 >= 192)
                {
                    if (num1 < 200 || num1 > 207)
                        throw new SerializingException("Invalid token in stream");
                    var num2 = (Byte) (num1 - 199U);
                    ReadPacked(out value, num2);
                }
                else
                    value = num1;
            }
            else if (num1 >= 128)
            {
                if (num1 < 176 || num1 > 191)
                    throw new SerializingException("Invalid token in stream");
                var num2 = (Byte) (num1 - 175U);
                ReadPacked(out value, num2);
            }
            else
                value = num1;
        }

        protected int BytesNeeded(UInt64 value)
        {
            for (var index = 7; index >= 0; --index)
                if (((Int64) value & (Int64) byte.MaxValue << index*8) != 0L)
                    return index + 1;

            return 0;
        }

        public void Write(UInt64 value)
        {
            if (TransportVersion > 1)
            {
                if (value < 192UL)
                    WriteByte((Byte) value);
                else
                {
                    var length = BytesNeeded(value);
                    WriteByte((Byte) (199 + length));
                    WritePacked(value, length);
                }
            }
            else if (value < 128UL)
                WriteByte((Byte) value);
            else
            {
                var length = BytesNeeded(value);
                WriteByte((Byte) (175 + length));
                WritePacked(value, length);
            }
        }

        protected void ReadPacked(out UInt64 value, int length)
        {
            value = 0UL;
            if (length > 8)
                return;

            var numArray = ReadBytes((uint) length);
            for (byte index = 0; (int) index < length; ++index)
                value = value << 8 | numArray[index];
        }

        protected void WritePacked(UInt64 value, int length)
        {
            var numArray = new byte[length];
            var bytes = BitConverter.GetBytes(value);
            for (var index = 0; index < length; ++index)
                numArray[index] = bytes[length - index - 1];
            WriteBytes(numArray);
        }

        public void Read(out uint a, out uint b)
        {
            var num = 0UL;
            if (Flags[3])
            {
                Read(out num);
                a = (UInt32) num;
                Read(out num);
                b = (UInt32) num;
            }
            else
            {
                Read(out num);
                a = (UInt32) num;
                b = (UInt32) num;
            }
        }

        public void Write(int a, int b)
        {
            if (Flags[3])
            {
                Write((UInt64) a);
                Write((UInt64) b);
            }
            else
            {
                if (a != b)
                    throw new SerializingException("counters must be equal for this stream type");

                Write((UInt64) a);
            }
        }

        public void Read(out Boolean value)
        {
            value = false;
            var num = ReadByte();
            if (TransportVersion > 1)
            {
                if (num == 1)
                    value = true;
                else if (num > 0)
                    throw new SerializingException("Invalid value for bool");
            }
            else if (num == 129)
                value = true;
            else if (num != 128)
                throw new SerializingException("Invalid token in stream");
        }

        public void Write(Boolean value)
        {
            if (TransportVersion > 1)
                WriteByte((Byte) (!value ? 0 : 1));
            else if (!value)
                WriteByte(128);
            else
                WriteByte(129);
        }

        public void Read(out float value)
        {
            value = 0.0f;
            if (TransportVersion > 1)
                value = BitConverter.ToSingle(BitConverter.GetBytes(ReadUInt()), 0);
            else
            {
                if (ReadByte() != 130)
                    throw new SerializingException("Invalid token in stream");

                value = BitConverter.ToSingle(BitConverter.GetBytes(ReadUInt()), 0);
            }
        }

        public void Write(Single value)
        {
            if (TransportVersion > 1)
                WriteBytes(BitConverter.GetBytes(value));
            else
            {
                WriteByte(130);
                WriteBytes(BitConverter.GetBytes(value));
            }
        }

        public void Read(out Byte[] data)
        {
            data = null;
            if (TransportVersion <= 1 && ReadByte() != 133)
                throw new SerializingException("Invalid token in stream");
            UInt64 num;
            Read(out num);
            data = ReadBytes((UInt32) num);
        }

        public void Write(Byte[] data)
        {
            if (TransportVersion <= 1)
                WriteByte(133);

            Write((UInt64) data.Length);
            WriteBytes(data);
        }

        public void Read(out String str)
        {
            str = "";
            if (TransportVersion <= 1 && ReadByte() != 137)
                throw new SerializingException("Invalid token in stream");

            UInt64 num;
            Read(out num);

            if (num == 0UL)
                return;

            str = Encoding.ASCII.GetString(ReadBytes((UInt32) num));
        }

        public void Write(String str)
        {
            if (TransportVersion <= 1)
                WriteByte(137);

            if (String.IsNullOrEmpty(str))
                Write(0UL);
            else
            {
                var bytes = Encoding.ASCII.GetBytes(str);
                Write((UInt64) bytes.Length);
                WriteBytes(bytes);
            }
        }

        public void ReadVersion(out UInt64 value)
        {
            value = 0UL;
            var num = ReadByte();
            if (TransportVersion > 1)
            {
                if (num != 209)
                    throw new SerializingException("Invalid token in stream");
            }
            else if (num != 254)
                throw new SerializingException("Invalid token in stream");

            Read(out value);
        }

        public void WriteVersion(UInt64 value)
        {
            WriteByte((Byte)(TransportVersion > 1 ? 209 : 254));
            Write(value);
        }

        public void CheckEnd()
        {
            byte num = ReadByte();
            if (TransportVersion > 1)
            {
                if (num != 211)
                    throw new SerializingException("Invalid token in stream");
            }
            else if (num != byte.MaxValue)
                throw new SerializingException("Invalid token in stream");
        }

        public void WriteEnd()
        {
            WriteByte(TransportVersion > 1 ? (Byte) 211 : Byte.MaxValue);
        }

        public void Read(out Int64 value)
        {
            value = 0L;
            if (TransportVersion > 1)
            {
                var num1 = ReadByte();
                if (num1 < 192)
                    value = num1;
                else if ((Byte) (num1 + 56U) > 7)
                {
                    if ((Byte) (num1 + 64U) > 7)
                    {
                        if (num1 != 208)
                            throw new SerializingException("Invalid token in stream");

                        value = Int64.MinValue;
                    }
                    var num2 = (Byte) (num1 - 191U);
                    UInt64 num3;
                    ReadPacked(out num3, num2);
                    value = -(Int64) num3;
                }
                else
                {
                    var num2 = (Byte) (num1 - 199U);
                    ulong num3;
                    ReadPacked(out num3, num2);
                    value = (Int64) num3;
                }
            }
            else
            {
                var num1 = ReadByte();
                if (num1 < 128)
                    value = num1;
                else if ((Byte) (num1 + 96U) > 15)
                {
                    if ((Byte) (num1 + 112U) > 15)
                    {
                        if (num1 != 143)
                            throw new SerializingException("Invalid token in stream");
                        value = long.MinValue;
                    }
                    var num2 = (Byte) (num1 - 143U);
                    UInt64 num3;
                    ReadPacked(out num3, num2);
                    value = -(Int64) num3;
                }
                else
                {
                    var num2 = (Byte) (num1 - 159U);
                    UInt64 num3;
                    ReadPacked(out num3, num2);
                    value = (Int64) num3;
                }
            }
        }

        public void Write(Int64 value)
        {
            if (TransportVersion > 1)
            {
                if (value >= 0L && value < 192L)
                    WriteByte((Byte) value);
                else if (value >= 192L)
                {
                    var num = (UInt64)value;
                    var length = BytesNeeded(num);
                    WriteByte((Byte) (199 + length));
                    WritePacked(num, length);
                }
                else if (value == Int64.MinValue)
                    WriteByte(208);
                else
                {
                    var num = (ulong) -value;
                    var length = BytesNeeded(num);
                    WriteByte((Byte) (191 + length));
                    WritePacked(num, length);
                }
            }
            else if (value >= 0L && value < 128L)
                WriteByte((Byte) value);
            else if (value >= 128L)
            {
                var num = (UInt64)value;
                var length = BytesNeeded(num);
                WriteByte((Byte) (159 + length));
                WritePacked(num, length);
            }
            else if (value == Int64.MinValue)
                WriteByte(143);
            else
            {
                var num = (ulong) -value;
                var length = BytesNeeded(num);
                WriteByte((Byte) (143 + length));
                WritePacked(num, length);
            }
        }
    }
}