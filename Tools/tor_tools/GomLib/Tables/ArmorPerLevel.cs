using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.Tables
{
    /// <summary>
    /// GomLib.Tables.ArmorPerLevel.TableData[ArmorSpec][Models.ItemQuality][ItemLevel][ArmorSlot]
    /// </summary>
    public static class ArmorPerLevel
    {
        class ArmorRow
        {
            public ArmorSpec Spec { get; set; }
            public ItemQuality Quality { get; set; }
            public int Level { get; set; }
            public Dictionary<SlotType, int> slotToRating { get; set; }
        }

        private static Dictionary<int, Dictionary<int, Dictionary<int, Dictionary<int, int>>>> table_data;
        // static string tablePath = "/resources/server/tbl/cbtarmorperleveltable.tbl";
        static string tablePath = "cbtArmorPerLevel";

        public static Dictionary<int, Dictionary<int, Dictionary<int, Dictionary<int, int>>>> TableData
        {
            get
            {
                if (table_data == null) { LoadData(); }
                return table_data;
            }
        }

        public static int GetArmor(Item i) { return GetArmor(i.ArmorSpec, i.ItemLevel, i.Quality, i.Slots.Count > 0 ? i.Slots[0] : SlotType.Invalid); }
        public static int GetArmor(ArmorSpec spec, int level, ItemQuality quality, SlotType slot)
        {
            if (level <= 0) { return 0; }

            if (table_data == null) { LoadData(); }

            return table_data[(int)spec][(int)quality][level][(int)slot];
        }

        private static void LoadData()
        {
            GomObject table = DataObjectModel.GetObject(tablePath);
            Dictionary<object, object> tableData = table.Data.ValueOrDefault<Dictionary<object,object>>("cbtArmorValues", null);

            // var rows = Utilities.ReadDataTable(tablePath, ReadArmorRow);
            table_data = new Dictionary<int, Dictionary<int, Dictionary<int, Dictionary<int, int>>>>();
            foreach (var kvp in tableData)
            {
                ArmorSpec armorSpec = ArmorSpecExtensions.ToArmorSpec((long)kvp.Key);
                Dictionary<object, object> qualityToLevelMap = (Dictionary<object, object>)kvp.Value;

                Dictionary<int, Dictionary<int, Dictionary<int, int>>> container0 = new Dictionary<int, Dictionary<int, Dictionary<int, int>>>();
                table_data[(int)armorSpec] = container0;

                foreach (var quality_level in qualityToLevelMap)
                {
                    ItemQuality quality = ItemQualityExtensions.ToItemQuality((ScriptEnum)quality_level.Key);
                    var levelToSlotMap = (Dictionary<object, object>)quality_level.Value;

                    Dictionary<int, Dictionary<int, int>> container1 = new Dictionary<int, Dictionary<int, int>>();
                    container0[(int)quality] = container1;

                    foreach (var level_slot in levelToSlotMap)
                    {
                        int level = (int)(long)level_slot.Key;
                        var slotToArmorMap = (Dictionary<object, object>)level_slot.Value;

                        Dictionary<int, int> container2 = new Dictionary<int, int>();
                        container1[level] = container2;

                        foreach (var slot_armor in slotToArmorMap)
                        {
                            SlotType slot = SlotTypeExtensions.ToSlotType((ScriptEnum)slot_armor.Key);
                            int armor = (int)(long)slot_armor.Value;
                            container2[(int)slot] = armor;
                        }
                    }
                }
            }
        }
    }
}
