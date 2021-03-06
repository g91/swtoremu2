﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.Tables
{
    /// <summary>
    /// GomLib.Tables.ArmorPerLevel.TableData[WeaponSpec][Models.ItemQuality][ItemLevel][Stat]<br/>
    /// Possible Stats: MaxWeaponDamage, MinWeaponDamage, ForcePowerRating, TechPowerRating
    /// </summary>
    public static class WeaponPerLevel
    {
        private static Dictionary<int, Dictionary<int, Dictionary<int, Dictionary<int, float>>>> table_data;
        static string tablePath = "cbtWeaponPerLevelPrototype";

        public static Dictionary<int, Dictionary<int, Dictionary<int, Dictionary<int, float>>>> TableData
        {
            get
            {
                if (table_data == null) { LoadData(); }
                return table_data;
            }
        }

        public static float GetStat(Item i, Stat stat) { return GetStat(i.WeaponSpec, i.ItemLevel, i.Quality, stat); }
        public static float GetStat(WeaponSpec spec, int level, ItemQuality quality, Stat stat)
        {
            if (level <= 0) { return 0; }

            if (table_data == null) { LoadData(); }

            return table_data[(int)spec][(int)quality][level][(int)stat];
        }

        private static void LoadData()
        {
            GomObject table = DataObjectModel.GetObject(tablePath);
            Dictionary<object, object> tableData = table.Data.Get<Dictionary<object,object>>("cbtWeaponPerLevelData");

            table_data = new Dictionary<int, Dictionary<int, Dictionary<int, Dictionary<int, float>>>>();
            foreach (var kvp in tableData)
            {
                WeaponSpec wpnSpec = WeaponSpecExtensions.ToWeaponSpec((ulong)kvp.Key);
                Dictionary<object, object> qualityToLevelMap = (Dictionary<object, object>)kvp.Value;

                var container0 = new Dictionary<int, Dictionary<int, Dictionary<int, float>>>();
                table_data[(int)wpnSpec] = container0;

                foreach (var quality_level in qualityToLevelMap)
                {
                    ItemQuality quality = ItemQualityExtensions.ToItemQuality((ScriptEnum)quality_level.Key);
                    var levelToStatMap = (Dictionary<object, object>)quality_level.Value;

                    var container1 = new Dictionary<int, Dictionary<int, float>>();
                    container0[(int)quality] = container1;

                    foreach (var level_stat in levelToStatMap)
                    {
                        int level = (int)(long)level_stat.Key;
                        var statToValueMap = (Dictionary<object, object>)level_stat.Value;

                        Dictionary<int, float> container2 = new Dictionary<int, float>();
                        container1[level] = container2;

                        foreach (var stat_val in statToValueMap)
                        {
                            Stat stat = StatExtensions.ToStat((ScriptEnum)stat_val.Key);
                            float val = (float)stat_val.Value;
                            container2[(int)stat] = val;
                        }
                    }
                }
            }
        }
    }
}
