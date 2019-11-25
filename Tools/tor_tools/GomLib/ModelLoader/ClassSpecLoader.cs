using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.ModelLoader
{
    public class ClassSpecLoader
    {
        static StringTable classNames;
        static Dictionary<ulong, Models.ClassSpec> idMap;
        static Dictionary<string, Models.ClassSpec> nameMap;

        static ClassSpecLoader()
        {
            classNames = StringTable.Find("str.gui.classnames");
            idMap = new Dictionary<ulong, Models.ClassSpec>();
            nameMap = new Dictionary<string, Models.ClassSpec>();
        }

        public static Models.ClassSpec Load(ulong nodeId)
        {
            Models.ClassSpec result;
            if (idMap.TryGetValue(nodeId, out result))
            {
                return result;
            }

            var obj = DataObjectModel.GetObject(nodeId);
            if (obj == null) { return null; }
            return Load(obj);
        }

        public static Models.ClassSpec Load(string fqn)
        {
            Models.ClassSpec result;
            if (nameMap.TryGetValue(fqn, out result))
            {
                return result;
            }

            var obj = DataObjectModel.GetObject(fqn);
            return Load(obj);
        }

        public static Models.ClassSpec Load(GomObject obj)
        {
            Models.ClassSpec spec = new Models.ClassSpec();

            spec.NodeId = obj.Id;
            spec.Fqn = obj.Name;
            spec.IsPlayerClass = obj.Name.StartsWith("class.pc.");
            spec.AbilityPackageId = obj.Data.ValueOrDefault<ulong>("field_4000000A1D72EA3A", 0);
            spec.AlignmentDark = (int)obj.Data.ValueOrDefault<float>("field_40000006A071472E", 0);
            spec.AlignmentLight = (int)obj.Data.ValueOrDefault<float>("field_40000006A071472D", 0);
            spec.Icon = obj.Data.ValueOrDefault<string>("chrClassDataIcon", null);
            spec.NameId = obj.Data.ValueOrDefault<long>("chrClassDataNameId", 0); // Index into str.gui.classnames
            spec.Id = (int)spec.NameId;
            spec.Name = classNames.GetText(spec.NameId, obj.Name);
            if (String.IsNullOrEmpty(spec.Name))
            {
                spec.Name = obj.Data.ValueOrDefault<string>("chrClassDataName", null);
            }

            idMap[obj.Id] = spec;
            nameMap[obj.Name] = spec;

            spec.AbilityPackage = AbilityPackageLoader.Load(spec.AbilityPackageId);

            return spec;
        }
    }
}
