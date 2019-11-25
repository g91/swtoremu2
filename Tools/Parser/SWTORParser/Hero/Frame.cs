using System;
using System.Text;

namespace SWTORParser.Hero
{
    public class Frame
    {
        protected byte[] Buffer;
        protected int readPosition;
        protected int writePosition;

        public Frame()
        {
            Buffer = null;
            readPosition = 0;
            writePosition = 0;
        }

        public Frame(byte[] data)
        {
            Buffer = data;
            readPosition = 0;
            writePosition = Buffer.Length;
        }

        public int ReadPosition
        {
            get { return readPosition; }
        }

        public void SeekToBegin()
        {
            readPosition = 0;
        }

        public int GetAvailForRead()
        {
            return writePosition - readPosition;
        }

        public int GetAvailForWrite()
        {
            if (Buffer == null)
                return 0;
            else
                return Buffer.Length - writePosition;
        }

        public int GetSize()
        {
            return writePosition;
        }

        public byte[] GetBuffer()
        {
            return Buffer;
        }

        public void CheckSize(int length)
        {
            if (Buffer == null)
            {
                Buffer = new byte[length];
            }
            else
            {
                if (GetAvailForWrite() >= length)
                    return;
                var numArray = new byte[Buffer.Length + length];
                Array.Copy(Buffer, numArray, Buffer.Length);
                Buffer = numArray;
            }
        }

        public void Write(bool value)
        {
            CheckSize(1);
            Buffer[writePosition] = value ? (byte) 1 : (byte) 0;
            ++writePosition;
        }

        public void Write(sbyte value)
        {
            CheckSize(1);
            Buffer[writePosition] = (byte) value;
            ++writePosition;
        }

        public void Write(byte value)
        {
            CheckSize(1);
            Buffer[writePosition] = value;
            ++writePosition;
        }

        public void Write(short value)
        {
            Write(BitConverter.GetBytes(value));
        }

        public void Write(ushort value)
        {
            Write(BitConverter.GetBytes(value));
        }

        public void Write(int value)
        {
            Write(BitConverter.GetBytes(value));
        }

        public void Write(uint value)
        {
            Write(BitConverter.GetBytes(value));
        }

        public void Write(long value)
        {
            Write(BitConverter.GetBytes(value));
        }

        public void Write(ulong value)
        {
            Write(BitConverter.GetBytes(value));
        }

        public void Write(float value)
        {
            Write(BitConverter.GetBytes(value));
        }

        public void Write(double value)
        {
            Write(BitConverter.GetBytes(value));
        }

        public void Write(string value)
        {
            if (value == null)
                value = "";
            byte[] bytes = Encoding.ASCII.GetBytes(value);
            Write(bytes.Length + 1);
            Write(bytes);
            Write((byte) 0);
        }

        public void Write(byte[] data)
        {
            Write(data, 0, data.Length);
        }

        public void Write(byte[] data, int offset, int length)
        {
            CheckSize(length);
            Array.Copy(data, offset, Buffer, writePosition, length);
            writePosition += length;
        }

        public void Write(uint[] data)
        {
            var num = (uint) data.Length;
            Write(num);
            for (uint index = 0U; index < num; ++index)
                Write(data[index]);
        }

        public void Write(ulong[] data)
        {
            var num = (uint) data.Length;
            Write(num);
            for (uint index = 0U; index < num; ++index)
                Write(data[index]);
        }

        public void WriteData(byte[] data)
        {
            if (data == null)
            {
                Write(0);
            }
            else
            {
                int length = data.Length;
                CheckSize(length + 4);
                Write(length);
                Array.Copy(data, 0, Buffer, writePosition, length);
                writePosition += length;
            }
        }

        public bool ReadBool()
        {
            if (GetAvailForRead() < 1)
                throw new EndOfBufferException();
            bool flag = BitConverter.ToBoolean(Buffer, readPosition);
            ++readPosition;
            return flag;
        }

        public byte ReadByte()
        {
            if (GetAvailForRead() < 1)
                throw new EndOfBufferException();
            byte num = Buffer[readPosition];
            ++readPosition;
            return num;
        }

        public sbyte ReadSByte()
        {
            if (GetAvailForRead() < 1)
                throw new EndOfBufferException();
            var num = (sbyte) Buffer[readPosition];
            ++readPosition;
            return num;
        }

        public short ReadShort()
        {
            if (GetAvailForRead() < 2)
                throw new EndOfBufferException();
            short num = BitConverter.ToInt16(Buffer, readPosition);
            readPosition += 2;
            return num;
        }

        public ushort ReadUShort()
        {
            if (GetAvailForRead() < 2)
                throw new EndOfBufferException();
            ushort num = BitConverter.ToUInt16(Buffer, readPosition);
            readPosition += 2;
            return num;
        }

        public int ReadInt()
        {
            if (GetAvailForRead() < 4)
                throw new EndOfBufferException();
            int num = BitConverter.ToInt32(Buffer, readPosition);
            readPosition += 4;
            return num;
        }

        public uint ReadUInt()
        {
            if (GetAvailForRead() < 4)
                throw new EndOfBufferException();
            uint num = BitConverter.ToUInt32(Buffer, readPosition);
            readPosition += 4;
            return num;
        }

        public long ReadLong()
        {
            if (GetAvailForRead() < 8)
                throw new EndOfBufferException();
            long num = BitConverter.ToInt64(Buffer, readPosition);
            readPosition += 8;
            return num;
        }

        public ulong ReadULong()
        {
            if (GetAvailForRead() < 8)
                throw new EndOfBufferException();
            ulong num = BitConverter.ToUInt64(Buffer, readPosition);
            readPosition += 8;
            return num;
        }

        public float ReadFloat()
        {
            if (GetAvailForRead() < 4)
                throw new EndOfBufferException();
            float num = BitConverter.ToSingle(Buffer, readPosition);
            readPosition += 4;
            return num;
        }

        public double ReadDouble()
        {
            if (GetAvailForRead() < 8)
                throw new EndOfBufferException();
            double num = BitConverter.ToDouble(Buffer, readPosition);
            readPosition += 8;
            return num;
        }

        public string ReadString()
        {
            int num = ReadInt();
            if (GetAvailForRead() < num)
                throw new EndOfBufferException();
            string @string = Encoding.ASCII.GetString(Buffer, readPosition, num - 1);
            readPosition += num;
            return @string;
        }

        public byte[] ReadBytes(int length)
        {
            if (GetAvailForRead() < length)
                throw new EndOfBufferException();
            var numArray = new byte[length];
            Array.Copy(Buffer, readPosition, numArray, 0, length);
            readPosition += length;
            return numArray;
        }

        public void ReadBytes(byte[] value)
        {
            ReadBytes(value, 0, value.Length);
        }

        public void ReadBytes(byte[] value, int length)
        {
            ReadBytes(value, 0, length);
        }

        public void ReadBytes(byte[] value, int offset, int length)
        {
            if (GetAvailForRead() < length)
                throw new EndOfBufferException();
            Array.Copy(Buffer, readPosition, value, offset, length);
            readPosition += length;
        }

        public byte[] ReadData()
        {
            uint num = ReadUInt();
            if (GetAvailForRead() < num)
                throw new EndOfBufferException();
            var numArray = new byte[num];
            Array.Copy(Buffer, readPosition, numArray, 0L, num);
            readPosition += (int) num;
            return numArray;
        }

        public uint[] ReadArrayUInt()
        {
            uint num = ReadUInt();
            var numArray = new uint[num];
            for (uint index = 0U; index < num; ++index)
                numArray[index] = ReadUInt();
            return numArray;
        }

        public ulong[] ReadArrayULong()
        {
            uint num = ReadUInt();
            var numArray = new ulong[num];
            for (uint index = 0U; index < num; ++index)
                numArray[index] = ReadULong();
            return numArray;
        }

        public void Empty()
        {
            Buffer = null;
            readPosition = 0;
            writePosition = 0;
        }

        #region Nested type: EndOfBufferException

        public class EndOfBufferException : Exception
        {
            public EndOfBufferException()
                : base("End of buffer reached.")
            {
            }
        }

        #endregion
    }
}