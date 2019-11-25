using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.Tables
{
    /// <summary>GomLib.Tables.ArmorPerLevel.TableData[ArmorSpec][quality][ilvl][ArmorSlot]</summary>
    public static class ItemModifierPackageTablePrototype
    {
        private static Dictionary<long, Dictionary<string, object>> item_modpkgprototype_data;
        static string itmModifierPackageTablePrototypePath = "itmModifierPackageTablePrototype";

        public static Dictionary<long, Dictionary<string, object>> TableData
        {
            get
            {
                if (item_modpkgprototype_data == null) { LoadData(); }
                return item_modpkgprototype_data;
            }
        }

        public static long GetModPkgNameId(long id)
        {
            if (item_modpkgprototype_data == null) { LoadData(); }
            return (long)item_modpkgprototype_data[id]["itmModPkgNameId"];
        }
        public static Dictionary<object, object> GetModPkgStatValues(long id)
        {
            if (item_modpkgprototype_data == null) { LoadData(); }
            return (Dictionary<object, object>)item_modpkgprototype_data[id]["itmModPkgAttributePercentages"];
        }

        private static void LoadData()
        {
            GomObject table = DataObjectModel.GetObject(itmModifierPackageTablePrototypePath);
            Dictionary<object, object> tableData = table.Data.Get<Dictionary<object, object>>("itmModifierPackages");
            item_modpkgprototype_data = new Dictionary<long, Dictionary<string, object>>();
            foreach (var kvp in tableData)
            {
                long modId = (long)kvp.Key;
                Dictionary<string, object> map = (Dictionary<string, object>)((GomLib.GomObjectData)kvp.Value).Dictionary;

                item_modpkgprototype_data[modId] = map;

                //List<List<int>> qData = new List<List<int>>();
                /*foreach (List<object> stats in qlist)
                {
                    var lvlData = new List<int>();
                    foreach (long stat in stats)
                    {
                        lvlData.Add((int)stat);
                    }
                    qData.Add(lvlData);
                }*/
                //item_modpkgprototype_data.Add((int)quality, qData);
            }
        }
    }
}
