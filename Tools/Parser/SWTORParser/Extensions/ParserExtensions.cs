using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SWTORParser.Extensions
{
    public static class ParserExtensions
    {
        public static StringBuilder AppendLine(this StringBuilder sb, String caption, Object val)
        {
            return sb.Append(caption).Append(": ").Append(val).AppendLine();
        }

        public static UInt64 ReadPackedInt(this EndianBinaryReader reader, Byte format)
        {
            if (format <= 1)
            {
                if (reader.CanRead(1))
                {
                    var a = reader.ReadByte();
                    if (a <= 127)
                        return a;

                    if ((Byte)(a + 80) <= 15)
                        return GetLong(reader.ReadBytes(a - 175));
                }
                return 0;
            }

            if (!reader.CanRead(1))
                return 0;

            var b = reader.ReadByte();

            if (b <= 191)
                return b;

            return (Byte)(b + 56) > 7 ? 0 : GetLong(reader.ReadBytes(b - 199));
        }

        public static UInt64 GetLong(Byte[] buffer)
        {
            var temp = new Byte[8];
            Array.Copy(buffer, 0, temp, 0, buffer.Length);
            return BitConverter.ToUInt64(temp, 0);
        }
    }
}
