using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.GomTypes
{
    public class ClassRef : GomType
    {
        public ClassRef() : base(GomTypeId.ClassRef) { }

        public ulong DomClassId { get; internal set; }
        public DomClass DomClass { get; internal set; }

        internal override void Link()
        {
            if (DomClassId != 0)
            {
                DomClass = DataObjectModel.Get<DomClass>(DomClassId);
            }
        }

        public override string ToString()
        {
            return System.String.Format("classref {0}", this.DomClass);
        }

        public override object ReadData(GomBinaryReader reader)
        {
            ulong instanceId = reader.ReadNumber();
            var gomObj = DataObjectModel.Get<GomObject>(instanceId);
            //if (gomObj != null)
            //{
            //    gomObj.Load();
            //}

            return gomObj;
        }
    }
}
