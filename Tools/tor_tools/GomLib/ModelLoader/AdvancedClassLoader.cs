using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.ModelLoader
{
    public class AdvancedClassLoader
    {
        const long StringOffset = 0x2F85F00000000;
        private static StringTable classNames;

        static AdvancedClassLoader()
        {
            classNames = StringTable.Find("str.gui.classnames");
        }

        public static Models.AdvancedClass Load(GomObject obj)
        {
            Models.AdvancedClass ac = new Models.AdvancedClass();
            ac.NodeId = obj.Id;
            ac.Fqn = obj.Name;
            ac.NameId = obj.Data.ValueOrDefault<long>("chrAdvancedClassDataNameId", 0);
            ac.Id = (int)ac.NameId;
            ac.Name = classNames.GetText(StringOffset + ac.NameId, ac.Fqn);
            ac.Packages = new List<Models.AbilityPackage>();
            ulong classSpecNodeId = obj.Data.ValueOrDefault<ulong>("chrAdvancedClassDataClassSpec", 0);
            ac.ClassSpec = ClassSpecLoader.Load(classSpecNodeId);
            return ac;
        }
    }
}
