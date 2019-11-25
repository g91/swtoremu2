using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.ModelLoader
{
    public class AbilityPackageLoader
    {
        private static Dictionary<string, Models.AbilityPackage> nameMap;
        private static Dictionary<ulong, Models.AbilityPackage> idMap;

        static AbilityPackageLoader()
        {
            nameMap = new Dictionary<string, Models.AbilityPackage>();
            idMap = new Dictionary<ulong, Models.AbilityPackage>();
        }

        public static Models.AbilityPackage Load(ulong nodeId)
        {
            Models.AbilityPackage pkg = null;
            if (idMap.TryGetValue(nodeId, out pkg))
            {
                return pkg;
            }

            var obj = DataObjectModel.GetObject(nodeId);
            return Load(obj);
        }

        public static Models.AbilityPackage Load(string fqn)
        {
            Models.AbilityPackage pkg = null;
            if (nameMap.TryGetValue(fqn, out pkg))
            {
                return pkg;
            }

            var obj = DataObjectModel.GetObject(fqn);
            return Load(obj);
        }

        public static Models.AbilityPackage Load(GomObject obj)
        {
            if (obj == null) { return null; }

            if (nameMap.ContainsKey(obj.Name))
            {
                return nameMap[obj.Name];
            }

            Models.AbilityPackage pkg = new Models.AbilityPackage();
            pkg.Id = obj.Name;
            pkg.NodeId = obj.Id;

            IDictionary<object, object> ablList = obj.Data.ValueOrDefault<IDictionary<object, object>>("ablPackageAbilitiesList", null);
            if (ablList != null)
            {
                PackageAbilityLoader pkgAblLoader = new PackageAbilityLoader();
                foreach (var kvp in ablList)
                {
                    // Load PackageAbility from kvp.Value
                    var pkgAbl = pkgAblLoader.Load((GomObjectData)kvp.Value);

                    // Add PackageAbility to pkg
                    pkg.PackageAbilities.Add(pkgAbl);
                }
            }

            nameMap[obj.Name] = pkg;
            idMap[obj.Id] = pkg;
            return pkg;
        }
    }
}
