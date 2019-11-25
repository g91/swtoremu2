using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.ModelLoader
{
    public class NpcLoader
    {
        const long NameLookupKey = -2761358831308646330;
        const long TitleLookupKey = -8863348193830878519;

        static Dictionary<ulong, Npc> idMap = new Dictionary<ulong, Npc>();
        static Dictionary<string, Npc> nameMap = new Dictionary<string, Npc>();
        static Dictionary<int, Npc> objIdMap = new Dictionary<int, Npc>();

        public string ClassName
        {
            get { return "chrNonPlayerCharacter"; }
        }

        public static Models.Npc Load(ulong nodeId)
        {
            Npc result;
            if (idMap.TryGetValue(nodeId, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(nodeId);
            Npc npc = new Npc();
            return Load(npc, obj);
        }

        public static Models.Npc Load(string fqn)
        {
            Npc result;
            if (nameMap.TryGetValue(fqn, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(fqn);
            Npc npc = new Npc();
            return Load(npc, obj);
        }

        public Models.GameObject CreateObject()
        {
            return new Models.Npc();
        }

        public static Models.Npc Load(Models.Npc npc, GomObject obj)
        {
            if (obj == null) { return npc; }
            if (npc == null) { return null; }

            ulong baseNpcId = obj.Data.ValueOrDefault<ulong>("npcParentSpecId", 0);
            Npc baseNpc;
            if (baseNpcId > 0)
            {
                baseNpc = Load(baseNpcId);
            }
            else
            {
                baseNpc = new Npc();
            }

            npc.Fqn = obj.Name;
            npc.NodeId = obj.Id;

            var textLookup = obj.Data.ValueOrDefault<Dictionary<object,object>>("locTextRetrieverMap", null);
            GomObjectData nameLookupData = (GomObjectData)textLookup[NameLookupKey];
            var nameId = nameLookupData.ValueOrDefault<long>("strLocalizedTextRetrieverStringID", 0);
            npc.Name = StringTable.TryGetString(npc.Fqn, nameLookupData);

            if (textLookup.ContainsKey(TitleLookupKey))
            {
                var titleLookupData = (GomObjectData)textLookup[TitleLookupKey];
                npc.Title = StringTable.TryGetString(npc.Fqn, titleLookupData);
            }

            npc.Id = (ulong)(nameId >> 32);

            //if (objIdMap.ContainsKey(npc.Id))
            //{
            //    Npc otherNpc = objIdMap[npc.Id];
            //    if (!String.Equals(otherNpc.Fqn, npc.Fqn))
            //    {
            //        throw new InvalidOperationException(String.Format("Duplicate NPC Ids: {0} and {1}", otherNpc.Fqn, npc.Fqn));
            //    }
            //}
            //else
            //{
            //    objIdMap[npc.Id] = npc;
            //}

            npc.MinLevel = (int)obj.Data.ValueOrDefault<long>("field_4000000027BDA14B", (long)baseNpc.MinLevel);
            npc.MaxLevel = (int)obj.Data.ValueOrDefault<long>("field_4000000027BDA14C", (long)baseNpc.MaxLevel);

            // Load Toughness
            var toughnessEnum = (ScriptEnum)obj.Data.ValueOrDefault<ScriptEnum>("field_40000005618EC27C", null);
            if (toughnessEnum == null)
            {
                npc.Toughness = baseNpc.Toughness;
            }
            else
            {
                npc.Toughness = ToughnessExtensions.ToToughness(toughnessEnum);
            }

            // Load Faction
            long factionId = obj.Data.ValueOrDefault<long>("npcFaction", 0);
            if (factionId == 0)
            {
                npc.Faction = baseNpc.Faction;
            }
            else
            {
                npc.Faction = FactionExtensions.ToFaction(factionId);
            }

            npc.DifficultyFlags = (int)obj.Data.ValueOrDefault<long>("spnDifficultyLevelFlags", baseNpc.DifficultyFlags);

            npc.LootTableId = obj.Data.ValueOrDefault<long>("field_40000009AF9F1222", baseNpc.LootTableId);

            ulong npcClass = obj.Data.ValueOrDefault<ulong>("npcClassPackage", 0);
            if (npcClass == 0)
            {
                npc.ClassSpec = baseNpc.ClassSpec;
            }
            else
            {
                npc.ClassSpec = ClassSpecLoader.Load(npcClass);
            }

            ulong cdxNodeId = obj.Data.ValueOrDefault<ulong>("npcCodexSpec", 0);
            if (cdxNodeId > 0)
            {
                npc.Codex = CodexLoader.Load(cdxNodeId);
            }
            else
            {
                npc.Codex = baseNpc.Codex;
            }

            var profTrained = (ScriptEnum)obj.Data.ValueOrDefault<ScriptEnum>("prfTrainerProfession", null);
            if (profTrained == null)
            {
                npc.ProfessionTrained = baseNpc.ProfessionTrained;
            }
            else
            {
                npc.ProfessionTrained = ProfessionExtensions.ToProfession(profTrained);
            }

            List<object> trainedPackages = obj.Data.ValueOrDefault<List<object>>("field_4000000A1D72EA38", null);
            if (trainedPackages == null)
            {
                npc.IsClassTrainer = baseNpc.IsClassTrainer;
            }
            else
            {
                npc.IsClassTrainer = trainedPackages.Count > 0;
            }

            npc.ConversationFqn = obj.Data.ValueOrDefault<string>("cnvConversationName", baseNpc.ConversationFqn);

            List<object> vendorPackages = obj.Data.ValueOrDefault<List<object>>("field_400000037C4DE713", null);
            if (vendorPackages != null)
            {
                foreach (string pkg in vendorPackages) { npc.VendorPackages.Add(pkg.ToLower()); }
            }
            else
            {
                npc.VendorPackages = baseNpc.VendorPackages;
            }

            return npc;
        }

        public void LoadObject(Models.GameObject loadMe, GomObject obj)
        {
            GomLib.Models.Npc npc = (Models.Npc)loadMe;
            Load(npc, obj);
        }

        public static void LoadReferences(Models.GameObject obj, GomObject gom)
        {
            var npc = (Npc)obj;

            ulong npcCharacterCompanionOverride = gom.Data.ValueOrDefault<ulong>("npcCharacterCompanionOverride", 0);
            if (npcCharacterCompanionOverride > 0)
            {
                npc.CompanionOverride = Load(npcCharacterCompanionOverride);
            }
            // No references to load
        }
    }
}
