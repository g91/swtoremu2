using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.Tables
{
    /// <summary>
    /// GomLib.Tables.ShieldPerLevel.TableData[ArmorSpec][Models.ItemQuality][ItemLevel][Stat]<br/>
    /// Possible stats: RangedShieldAbsorb, ForcePowerRating, MeleeShieldAbsorb, TechPowerRating, MeleeShieldChance, RangedShieldChance
    /// </summary>
    public static class ShieldPerLevel
    {
        private static Dictionary<int, Dictionary<int, Dictionary<int, Dictionary<int, float>>>> table_data;
        static string tablePath = "cbtShieldPerLevel";

        public static Dictionary<int, Dictionary<int, Dictionary<int, Dictionary<int, float>>>> TableData
        {
            get
            {
                if (table_data == null) { LoadData(); }
                return table_data;
            }
        }

        /// <summary>
        /// Stat.RangedShieldAbsorb, Stat.ForcePowerRating, Stat.MeleeShieldAbsorb, Stat.TechPowerRating, Stat.MeleeShieldChance, Stat.RangedShieldChance
        /// </summary>
        public static float GetShield(Item i, Stat stat) { return GetShield(i.ArmorSpec, i.Quality, i.ItemLevel, stat); }
        public static float GetShield(ArmorSpec spec, ItemQuality quality, int Level, Stat stat)
        {
            if (table_data == null) { LoadData(); }

            return table_data[(int)spec][(int)quality][Level][(int)stat];
        }

        private static void LoadData()
        {
            GomObject table = DataObjectModel.GetObject(tablePath);
            Dictionary<object, object> tableData = table.Data.Get<Dictionary<object,object>>("cbtShieldStatMap");

            table_data = new Dictionary<int, Dictionary<int, Dictionary<int, Dictionary<int, float>>>>();
            foreach (var kvp in tableData)
            {
                //WeaponSpec wpnSpec = WeaponSpecExtensions.ToWeaponSpec((ulong)kvp.Key);
                ArmorSpec spec = ArmorSpecExtensions.ToArmorSpec((long)kvp.Key);
                Dictionary<object, object> qualityToLevelMap = (Dictionary<object, object>)kvp.Value;

                var container0 = new Dictionary<int, Dictionary<int, Dictionary<int, float>>>();
                table_data[(int)spec] = container0;

                foreach (var quality_level in qualityToLevelMap)
                {
                    ItemQuality quality = ItemQualityExtensions.ToItemQuality((ScriptEnum)quality_level.Key);
                    var levelToStatMap = (Dictionary<object, object>)quality_level.Value;

                    var container1 = new Dictionary<int, Dictionary<int, float>>();
                    container0[(int)quality] = container1;

                    foreach (var level_stat in levelToStatMap)
                    {
                        int level = (int)(long)level_stat.Key;
                        var shieldStats = (GomObjectData)level_stat.Value;

                        Dictionary<int, float> container2 = new Dictionary<int, float>();
                        container1[level] = container2;
                        container2[(int)Stat.RangedShieldAbsorb] = shieldStats.ValueOrDefault<float>("cbtRangeAbsorb", 0);
                        container2[(int)Stat.ForcePowerRating] = shieldStats.ValueOrDefault<float>("cbtShieldForcePower", 0);
                        container2[(int)Stat.MeleeShieldAbsorb] = shieldStats.ValueOrDefault<float>("cbtMeleeAbsorb", 0);
                        container2[(int)Stat.TechPowerRating] = shieldStats.ValueOrDefault<float>("cbtShieldTechPower", 0);
                        container2[(int)Stat.MeleeShieldChance] = shieldStats.ValueOrDefault<float>("cbtMeleeChance", 0);
                        container2[(int)Stat.RangedShieldChance] = shieldStats.ValueOrDefault<float>("cbtRangeChance", 0);
                    }
                }
            }
        }
    }
}
