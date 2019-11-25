namespace GomLib.Tables
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using GomLib.Models;

    /// <summary>GomLib.Tables.ArmorPerLevel.TableData[ArmorSpec][quality][ilvl][ArmorSlot]</summary>
    public static class SchematicVariationsPrototype
    {
        private static Dictionary<ulong, Dictionary<int, int>> prf_schemvarprototype_data;
        static string prfSchematicVariationsPrototypePath = "prfSchematicVariationsPrototype";

        public static Dictionary<ulong, Dictionary<int, int>> TableData
        {
            get
            {
                if (prf_schemvarprototype_data == null) { LoadData(); }
                return prf_schemvarprototype_data;
            }
        }

        public static int GetModPkgTblPrototype(ulong id, int variant)
        {
            //if (level <= 0) { return new List<ulong>(); }

            if (prf_schemvarprototype_data == null) { LoadData(); }

            return prf_schemvarprototype_data[id][variant];
        }

private static void LoadData()
{
    GomObject table = DataObjectModel.GetObject(prfSchematicVariationsPrototypePath);
    Dictionary<object, object> tableData = table.Data.Get<Dictionary<object, object>>("prfSchematicVariationMasterList");
    prf_schemvarprototype_data = new Dictionary<ulong, Dictionary<int, int>>();
    foreach (var kvp in tableData)
    {
        ulong itemid = (ulong)kvp.Key;
        Dictionary<object, object> qlist = (Dictionary<object, object>)kvp.Value;

        Dictionary<int, Dictionary<int, Dictionary<int, int>>> container0 = new Dictionary<int, Dictionary<int, Dictionary<int, int>>>();

        Dictionary<int, int> qData = new Dictionary<int, int>();
        foreach (var kvp2 in qlist)
        {
            qData[(int)(long)kvp2.Key] = (int)(long)kvp2.Value;
        }
        prf_schemvarprototype_data.Add(itemid, qData);
    }
}
    }
}
