using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

using SWTORParser.Hero;
namespace SWTORParser.Extensions
{
    public static class ReadHelper
    {
        public static Field DeserializeField(EndianBinaryReader reader, Byte format)
        {
            var f = new Field
            {
                FieldId = reader.ReadPackedInt(format),
                FieldType = (HeroTypes)Enum.Parse(typeof(HeroTypes), reader.ReadPackedInt(format).ToString(CultureInfo.InvariantCulture))
            };
            f.Data = DeserializeType(reader, f.FieldType, format);
            return f;
        }

        public static Object DeserializeType(EndianBinaryReader reader, HeroTypes type, Byte format)
        {
            switch (type)
            {
                case HeroTypes.Integer:
                    return DeserializeInteger(reader, format);

                case HeroTypes.Id:
                    return DeserializeInteger(reader, format);

                case HeroTypes.Boolean:
                    return DeserializeBoolean(reader, format);

                case HeroTypes.Float:
                    return DeserializeSingle(reader, format);

                case HeroTypes.Enum:
                    return DeserializeInteger(reader, format);

                case HeroTypes.List:
                    return DeserializeList(reader, format);

                case HeroTypes.Vector3:
                    return DeserializeVector3(reader, format);

                default:
                    return null;
            }
        }

        // HeroInteger
        // HeroId
        // HeroEnum
        public static UInt64 DeserializeInteger(EndianBinaryReader reader, Byte format)
        {
            return reader.ReadPackedInt(format);
        }

        // HeroBoolean
        public static Boolean DeserializeBoolean(EndianBinaryReader reader, Byte format)
        {
            if (format > 1)
                return reader.ReadByte() == 1;

            return reader.ReadByte() == 129;
        }

        // HeroFloat
        public static Single DeserializeSingle(EndianBinaryReader reader, Byte format)
        {
            if (format > 1)
                return reader.ReadSingle();

            return reader.ReadByte() == 130 ? reader.ReadSingle() : 0.0f;
        }

        // HeroString
        public static String DeserializeString(EndianBinaryReader reader, Byte format)
        {
            return Encoding.UTF8.GetString(reader.ReadBytes((Int32) reader.ReadPackedInt(format)));
        }

        // HeroList
        public static List<Field> DeserializeList(EndianBinaryReader reader, Byte format)
        {
            //var type = HeroTypes.None;

            if (!IsByte8Set(5))
                /*type = (HeroTypes) */Enum.Parse(typeof (HeroTypes), reader.ReadPackedInt(format).ToString(CultureInfo.InvariantCulture));

            /*var counter1 = */reader.ReadPackedInt(format);
            var counter2 = reader.ReadPackedInt(format);

            var fL = new List<Field>((Int32) counter2);

            for (var i = 0UL; i < counter2; ++i)
                fL.Add(DeserializeField(reader, format));

            return fL;
        }

        // HeroLookupList

        // HeroVector3
        public static Tuple<Single, Single, Single> DeserializeVector3(EndianBinaryReader reader, Byte format)
        {
            return new Tuple<Single, Single, Single>(DeserializeSingle(reader, format), DeserializeSingle(reader, format), DeserializeSingle(reader, format));
        }

        public static Boolean IsByte4Set(Byte style)
        {
            return false;
        }

        public static Boolean IsByte5Set(Byte style)
        {
            return false;
        }

        public static Boolean IsByte6Set(Byte style)
        {
            return false;
        }

        public static Boolean IsByte7Set(Byte style)
        {
            return false;
        }

        public static Boolean IsByte8Set(Byte style)
        {
            return false;
        }
    }

    public class Field
    {
        public HeroTypes FieldType;
        public UInt64 FieldId;
        public Object Data;
    }
}
