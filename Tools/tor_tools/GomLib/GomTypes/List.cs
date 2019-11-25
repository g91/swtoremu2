using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.GomTypes
{
    public class List : GomType
    {
        public List() : base(GomTypeId.List) { }

        public GomType ContainedType { get; internal set; }

        internal override void Link()
        {
            ContainedType.Link();
        }

        public override string ToString()
        {
            return System.String.Format("List<{0}>", ContainedType);
        }

        public override object ReadData(GomBinaryReader reader)
        {
            GomType itemType = GomTypeLoader.Load(reader, false);
            if ((ContainedType != null) && (itemType.TypeId == ContainedType.TypeId))
            {
                itemType = ContainedType;
            }

            int len = (int)reader.ReadNumber();
            int len2 = (int)reader.ReadNumber();
            if (len != len2)
            {
                throw new InvalidOperationException("List length values aren't the same?!");
            }

            List<object> result = new List<object>(len);

            for (var i = 0; i < len; i++)
            {
                var idx = reader.ReadNumber();
                var val = itemType.ReadItem(reader);
                result.Add(val);
            }

            return result;
        }

        //public override object ReadItem(GomBinaryReader reader)
        //{

        //    return base.ReadItem(reader);
        //}
    }
}
