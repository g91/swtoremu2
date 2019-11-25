using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.ModelLoader
{
    public class PackageAbilityLoader
    {
        static StringTable strTable;

        static PackageAbilityLoader()
        {
            strTable = StringTable.Find("str.abl.player.skill_trees");
        }

        public Models.PackageAbility Load(GomObjectData gomObj)
        {
            GomObjectData obj = gomObj;
            Models.PackageAbility result = new Models.PackageAbility();
            result.AbilityId = obj.ValueOrDefault<ulong>("ablAbilityDataSpec", 0);
            result.AutoAcquire = gomObj.ValueOrDefault<bool>("ablAbilityDataAutoAcquire", false);
            // result.CategoryName = 
            // result.CategoryNameId

            // result.IsTalent
            result.PackageId = obj.ValueOrDefault<ulong>("ablAbilityDataPackage", 0);
            List<object> ranks = obj.ValueOrDefault<List<object>>("ablAbilityDataRanks", null);
            foreach (var rank in ranks)
            {
                result.Levels.Add((int)(long)rank);
            }
            if (result.Levels.Count > 0)
            {
                result.Level = result.Levels[0];
            }
            result.Scales = (result.Levels.Count == 50);
            // result.Rank = 
            // result.Toughness =

            result.Ability = AbilityLoader.Load(result.AbilityId);
            return result;
        }
    }
}
