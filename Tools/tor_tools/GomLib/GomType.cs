﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib
{
    public enum GomTypeId : byte
    {
        UInt64 = 0x01,
        Int64 = 0x02,
        Boolean = 0x03,
        Float = 0x04,
        Enum = 0x05, // Followed by GUID
        String = 0x06,
        List = 0x07, // Followed by an additional type: List type
        Map = 0x08, // Followed by two additional types: Map From and Map To)
        EmbeddedClass = 0x09, // Possible Object Reference - Followed by GUID
        Array = 0x0B, // Followed by a byte then a type (1D Array)
        Table = 0x0C, // Followed by two bytes then a type (2D Array)
        Cubic = 0x0D, // Followed by 3 bytes then a type (3D Array)
        Script = 0x0E,
        ClassRef = 0x0F, // Possible Object Reference - Followed by GUID
        Timer = 0x11,
        Vec3 = 0x12,
        TimeSpan = 0x14,
        Time = 0x15
    }

    public abstract class GomType
    {
        public GomTypeId TypeId { get; private set; }
        //public UInt64 ReferenceId { get; private set; }
        //public GomObject ReferenceObject { get; private set; }

        //public GomType ContainedType { get; private set; }
        //public GomType MappedType { get; private set; }

        protected GomType(GomTypeId typeId)
        {
            this.TypeId = typeId;
        }

        internal virtual void Link() { }

        public virtual bool ConfirmType(GomBinaryReader reader)
        {
            byte typeByte = reader.ReadByte();
            return typeByte == (byte)this.TypeId;
        }

        public abstract object ReadData(GomBinaryReader reader);
        public virtual object ReadItem(GomBinaryReader reader)
        {
            return ReadData(reader);
        }

        //public void Associate(Dictionary<ulong, GomObject> objLookup)
        //{
        //    if (this.ReferenceId != 0) { this.ReferenceObject = objLookup[this.ReferenceId]; }
        //    if (this.ContainedType != null) { this.ContainedType.Associate(objLookup); }
        //    if (this.MappedType != null) { this.MappedType.Associate(objLookup); }
        //}

        //public void Parse(GomBinaryReader reader)
        //{
        //    byte typeStart = reader.ReadByte();
        //    if (typeStart != 0xFE)
        //    {
        //        throw new InvalidOperationException("Type must begin with byte 0xFE");
        //    }

        //    reader.ReadByte(); // Unknown, always 0
        //    this.TypeId = (GomTypeId)reader.ReadByte();

        //    switch (this.TypeId)
        //    {
        //        case GomTypeId.Boolean:
        //        case GomTypeId.Int64:
        //        case GomTypeId.String:
        //        case GomTypeId.Time:
        //        case GomTypeId.Timer:
        //        case GomTypeId.TimeSpan:
        //        case GomTypeId.UInt64:
        //        case GomTypeId.Float:
        //        case GomTypeId.Vec3:
        //        case GomTypeId.Script:
        //            // No additional work for these types
        //            break;
        //        case GomTypeId.Table:
        //            reader.ReadBytes(2); // Dimension sizes
        //            this.ContainedType = reader.ReadGomType();
        //            break;
        //        case GomTypeId.Cubic:
        //            reader.ReadBytes(3); // Dimension sizes
        //            this.ContainedType = reader.ReadGomType();
        //            break;
        //        case GomTypeId.Enum:
        //        case GomTypeId.EmbeddedClass:
        //        case GomTypeId.ClassRef:
        //            // Must read referenced id
        //            TypedValue tval = reader.ReadTypedValue();
        //            this.ReferenceId = tval.AsNumber();
        //            break;
        //        case GomTypeId.Array:
        //            reader.ReadByte();
        //            this.ContainedType = reader.ReadGomType();
        //            break;
        //        case GomTypeId.List:
        //            // Read Contained Type
        //            this.ContainedType = reader.ReadGomType();
        //            break;
        //        case GomTypeId.Map:
        //            // Read Map From and To types
        //            this.ContainedType = reader.ReadGomType();
        //            this.MappedType = reader.ReadGomType();
        //            break;
        //        default:
        //            throw new InvalidOperationException(String.Format("Unknown GomType ID: {0:X}", (byte)this.TypeId));
        //    }

        //    byte typeEnd = reader.ReadByte();
        //    if (typeEnd != 0xFF)
        //    {
        //        throw new InvalidOperationException("Type must end with byte 0xFF");
        //    }
        //}

        //public override string ToString()
        //{
        //    switch (this.TypeId)
        //    {
        //        case GomTypeId.Boolean:
        //            return "bool";
        //        case GomTypeId.Int64:
        //            return "int32";
        //        case GomTypeId.String:
        //            return "string";
        //        case GomTypeId.Time:
        //            return "time";
        //        case GomTypeId.Timer:
        //            return "timer";
        //        case GomTypeId.TimeSpan:
        //            return "timespan";
        //        case GomTypeId.UInt64:
        //            return "uint64";
        //        case GomTypeId.Float:
        //            return "float";
        //        case GomTypeId.Vec3:
        //            return "Vector3";
        //        case GomTypeId.Script:
        //            return "Script";
        //        case GomTypeId.Enum:
        //            return String.Format("enum {0}", this.ReferenceObject);
        //        case GomTypeId.EmbeddedClass:
        //            return String.Format("class {0}", this.ReferenceObject);
        //        case GomTypeId.ClassRef:
        //            return String.Format("classref {0}", this.ReferenceObject);
        //        case GomTypeId.Array:
        //            return String.Format("Array<{0}>", this.ContainedType);
        //        case GomTypeId.List:
        //            return String.Format("List<{0}>", this.ContainedType);
        //        case GomTypeId.Map:
        //            return String.Format("Map<{0},{1}>", this.ContainedType, this.MappedType);
        //        case GomTypeId.Table:
        //            return String.Format("2DArray<{0}>", this.ContainedType);
        //        case GomTypeId.Cubic:
        //            return String.Format("3dArray<{0}>", this.ContainedType);
        //        default:
        //            throw new InvalidOperationException(String.Format("Unknown GomType ID: {0:X}", (byte)this.TypeId));
        //    }
        //}
    }
}
