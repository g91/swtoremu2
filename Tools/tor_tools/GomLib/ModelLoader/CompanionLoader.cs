using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.ModelLoader
{
    public class CompanionLoader
    {
        static StringTable strTable;

        static CompanionLoader()
        {
            strTable = StringTable.Find("str.sys.worldmap");
        }

        public string ClassName
        {
            get { return "chrCompanionInfoRow"; }
        }

        public static Models.Companion Load(Models.Companion cmp, ulong npcId, GomObjectData obj)
        {
            if (obj == null) { return cmp; }
            if (cmp == null) { return null; }

            IDictionary<string, object> objAsDict = obj.Dictionary;
            cmp.Npc = NpcLoader.Load(npcId);
            cmp.Name = cmp.Npc.Name;
            cmp.Id = cmp.Npc.Id;
            cmp.Portrait = ParsePortrait((string)obj.Dictionary["chrCompanionInfo_portrait"]);
            cmp.ConversationMultiplier = (float)obj.Dictionary["chrCompanionInfo_affectionMultiplier"];
            cmp.Classes = new List<ClassSpec>();

            Dictionary<object, object> profMods = (Dictionary<object,object>)obj.Dictionary["chrCompanionInfo_profession_modifiers"];
            cmp.ProfessionModifiers = new List<CompanionProfessionModifier>();
            foreach (var profKvp in profMods)
            {
                CompanionProfessionModifier mod = new CompanionProfessionModifier();
                mod.Companion = cmp;
                mod.Stat = StatExtensions.ToStat((ScriptEnum)profKvp.Key);
                mod.Modifier = (int)(long)profKvp.Value;
                cmp.ProfessionModifiers.Add(mod);
            }

            Dictionary<object, object> giftInterestMap = (Dictionary<object,object>)obj.Dictionary["chrCompanionInfo_gift_interest_unromanced_map"];
            cmp.GiftInterest = new List<CompanionGiftInterest>();
            foreach (var giftKvp in giftInterestMap)
            {
                CompanionGiftInterest cgi = new CompanionGiftInterest();
                cgi.Companion = cmp;
                cgi.GiftType = GiftTypeExtensions.ToGiftType((ScriptEnum)giftKvp.Key);
                cgi.Reaction = GiftInterestExtensions.ToGiftInterest((ScriptEnum)giftKvp.Value);
                cmp.GiftInterest.Add(cgi);
            }

            giftInterestMap = (Dictionary<object,object>)obj.Dictionary["chrCompanionInfo_gift_interest_romanced_map"];
            foreach (var giftKvp in giftInterestMap)
            {
                GiftType gftType = GiftTypeExtensions.ToGiftType((ScriptEnum)giftKvp.Key);
                var cgi = cmp.GiftInterest.First(x => x.GiftType == gftType);
                cgi.RomancedReaction = GiftInterestExtensions.ToGiftInterest((ScriptEnum)giftKvp.Value);
                cmp.IsRomanceable = true;
            }
            if (!cmp.IsRomanceable)
            {
                // Force Malavai Quinn and Lt. Pierce to be listed as romanceable
                if (cmp.Name.Contains("Quinn") || (cmp.Name.Contains("Pierce"))) { cmp.IsRomanceable = true; }
            }

            cmp.AffectionRanks = new List<CompanionAffectionRank>();
            List<object> affectionRanks = (List<object>)obj.Dictionary["chrCompanionInfo_threshold_list"];
            int rank = 0;
            foreach (long aff in affectionRanks)
            {
                CompanionAffectionRank car = new CompanionAffectionRank();
                car.Companion = cmp;
                car.Rank = rank;
                car.Affection = (int)aff;
                cmp.AffectionRanks.Add(car);
                rank++;
            }

            return cmp;
        }

        private static string ParsePortrait(string portrait)
        {
            // Remove img:/
            portrait = portrait.Substring(5).ToLower();

            TorLib.Icons.AddPortrait(portrait);

            // Parse filename
            var filename = System.IO.Path.GetFileNameWithoutExtension(portrait);
            return filename;
        }

        public static void LoadReferences(Models.GameObject obj, GomObject gom)
        {
            // No references to load
        }
    }
}
