using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.GomTypes
{
    public class Enum : GomType
    {
        public Enum() : base(GomTypeId.Enum) { }

        public ulong DomEnumId { get; internal set; }
        public DomEnum DomEnum { get; internal set; }

        internal override void Link()
        {
            DomEnum = DataObjectModel.Get<DomEnum>(DomEnumId);
        }

        public override string ToString()
        {
            return System.String.Format("enum {0}", this.DomEnum);
        }

        public override object ReadData(GomBinaryReader reader)
        {
            ScriptEnum result = new ScriptEnum();

            byte val = (byte)reader.ReadNumber();
            result.Value = val;
            result.EnumType = this.DomEnum;

            return result;
        }
    }
}
