using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.ModelLoader
{
    public class QuestLoader
    {
        const long strOffset = 0x35D0200000000;

        static Dictionary<ulong, Quest> idMap = new Dictionary<ulong, Quest>();
        static Dictionary<string, Quest> nameMap = new Dictionary<string, Quest>();

        public string ClassName
        {
            get { return "qstQuestDefinition"; }
        }

        public static Models.Quest Load(ulong nodeId)
        {
            Quest result;
            if (idMap.TryGetValue(nodeId, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(nodeId);
            Quest qst = new Quest();
            return Load(qst, obj);
        }

        public static Models.Quest Load(string fqn)
        {
            Quest result;
            if (nameMap.TryGetValue(fqn, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(fqn);
            Quest qst = new Quest();
            return Load(qst, obj);
        }

        public Models.GameObject CreateObject()
        {
            return new Models.Quest();
        }

        public static Models.Quest Load(Models.Quest qst, GomObject obj)
        {
            if (obj == null) { return qst; }
            if (qst == null) { return null; }

            qst.Fqn = obj.Name;
            qst.NodeId = obj.Id;

            var textMap = (Dictionary<object, object>)obj.Data.ValueOrDefault<Dictionary<object, object>>("locTextRetrieverMap", null);
            qst.TextLookup = textMap;

            long questGuid = obj.Data.ValueOrDefault<long>("qstQuestDefinitionGUID", 0);
            qst.Id = (ulong)(questGuid >> 32);
            qst.RequiredLevel = (int)obj.Data.ValueOrDefault<long>("qstReqMinLevel", 0);
            qst.IsRepeatable = obj.Data.ValueOrDefault<bool>("qstIsRepeatable", false);
            qst.XpLevel = (int)obj.Data.ValueOrDefault<long>("qstXpLevel", 0);
            qst.Difficulty = QuestDifficultyExtensions.ToQuestDifficulty((ScriptEnum)obj.Data.ValueOrDefault<ScriptEnum>("qstDifficulty", null));
            qst.CanAbandon = obj.Data.ValueOrDefault<bool>("qstAllowAbandonment", false);
            qst.Icon = obj.Data.ValueOrDefault<string>("qstMissionIcon", null);
            qst.IsHidden = obj.Data.ValueOrDefault<bool>("qstIsHiddenQuest", false);
            qst.IsClassQuest = obj.Data.ValueOrDefault<bool>("qstIsClassQuest", false);
            qst.IsBonus = obj.Data.ValueOrDefault<bool>("qstIsBonusQuest", false);
            qst.BonusShareable = obj.Data.ValueOrDefault<bool>("qstIsBonusQuestShareable", false);
            qst.CategoryId = obj.Data.ValueOrDefault<long>("qstCategoryDisplayName", 0);
            qst.Category = QuestCategoryExtensions.ToQuestCategory(qst.CategoryId);

            LoadBranches(qst, obj);
            var items = (List<object>)obj.Data.ValueOrDefault<List<object>>("qstItemVariableDefinition_ProtoVarList", null);
            var bools = (List<object>)obj.Data.ValueOrDefault<List<object>>("qstSimpleBoolVariableDefinition_ProtoVarList", null);
            var strings = (List<object>)obj.Data.ValueOrDefault<List<object>>("qstStringIdVariableDefinition_ProtoVarList", null);
            LoadRequiredClasses(qst, obj);

            long nameId = questGuid + 0x58;
            var nameLookup = (GomObjectData)textMap[nameId];
            qst.Name = StringTable.TryGetString(qst.Fqn, nameLookup);

            if (qst.Name.StartsWith("CUT", StringComparison.InvariantCulture))
            {
                qst.IsHidden = true;
            }

            TorLib.Icons.AddCodex(qst.Icon);

            return qst;
        }

        private static void LoadRequiredClasses(Quest qst, GomObject obj)
        {
            qst.Classes = new List<ClassSpec>();
            var reqClasses = (Dictionary<object, object>)obj.Data.ValueOrDefault<Dictionary<object, object>>("qstReqClasses", null);
            if (reqClasses != null)
            {
                foreach (var kvp in reqClasses)
                {
                    var spec = ClassSpecLoader.Load((ulong)kvp.Key);
                    var enabled = (bool)kvp.Value;
                    if (enabled)
                    {
                        qst.Classes.Add(spec);
                    }
                }
            }
        }

        private static void LoadBranches(Quest qst, GomObject obj)
        {
            var branches = (List<object>)obj.Data.ValueOrDefault<List<object>>("qstBranches", null);
            qst.Branches = new List<QuestBranch>();
            if (branches != null)
            {
                foreach (var br in branches)
                {
                    var branch = QuestBranchLoader.Load((GomObjectData)br, qst);
                    branch.Quest = qst;
                    qst.Branches.Add(branch);
                }
            }
        }

        public void LoadObject(Models.GameObject loadMe, GomObject obj)
        {
            GomLib.Models.Quest qst = (Models.Quest)loadMe;
            Load(qst, obj);
        }

        public void LoadReferences(Models.GameObject obj, GomObject gom)
        {
            // No references to load
        }
    }
}
