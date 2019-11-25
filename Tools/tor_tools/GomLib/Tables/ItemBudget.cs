using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.Tables
{
    /// <summary>
    /// GomLib.Tables.ArmorPerLevel.TableData[ArmorSpec][quality][ilvl][ArmorSlot]
    /// </summary>
    public static class ItemBudget
    {
        private static Dictionary<int, List<List<int>>> item_budget_data;
        static string itmBudgetTablePath = "itmBudgetedAttributesPrototype";

        public static Dictionary<int, List<List<int>>> TableData
        {
            get
            {
                if (item_budget_data == null) { LoadData(); }
                return item_budget_data;
            }
        }

        public static List<int> GetBudget(Item i) { return GetBudget(i.Quality, i.ItemLevel); }
        public static List<int> GetBudget(Models.ItemQuality quality, int level)
        {
            if (level <= 0) { return new List<int>(); }

            if (item_budget_data == null) { LoadData(); }

            return item_budget_data[(int)quality][level];
        }

        private static void LoadData()
        {
            GomObject table = DataObjectModel.GetObject(itmBudgetTablePath);
            Dictionary<object, object> tableData = table.Data.Get<Dictionary<object, object>>("itmBudgetedAttributes");
            item_budget_data = new Dictionary<int, List<List<int>>>();
            foreach (var kvp in tableData)
            {
                Models.ItemQuality quality = Models.ItemQualityExtensions.ToItemQuality((ScriptEnum)kvp.Key);
                var qlist = (List<object>)kvp.Value;

                List<List<int>> qData = new List<List<int>>();
                foreach (List<object> stats in qlist)
                {
                    var lvlData = new List<int>();
                    foreach (long stat in stats)
                    {
                        lvlData.Add((int)stat);
                    }
                    qData.Add(lvlData);
                }
                item_budget_data.Add((int)quality, qData);
            }
        }
    }
}
