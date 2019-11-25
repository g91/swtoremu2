using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.ModelLoader
{
    public class ConversationLoader
    {
        static Dictionary<ulong, Conversation> idMap = new Dictionary<ulong, Conversation>();
        static Dictionary<string, Conversation> nameMap = new Dictionary<string, Conversation>();

        static Dictionary<long, Npc> companionShortNameMap = new Dictionary<long, Npc>();

        public string ClassName
        {
            get { return "cnvTree_Prototype"; }
        }

        public static Models.Conversation Load(ulong nodeId)
        {
            Conversation result;
            if (idMap.TryGetValue(nodeId, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(nodeId);
            Conversation cnv = new Conversation();
            return Load(cnv, obj);
        }

        public static Models.Conversation Load(string fqn)
        {
            Conversation result;
            if (nameMap.TryGetValue(fqn, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(fqn);
            Conversation cnv = new Conversation();
            return Load(cnv, obj);
        }

        public static Conversation Load(Conversation cnv, GomObject obj)
        {
            if (obj == null) { return null; }
            if (cnv == null) { return null; }

            cnv.Fqn = obj.Name;
            // cnv.Id = 

            var dialogNodeMap = obj.Data.Get<Dictionary<object, object>>("cnvTreeDialogNodes_Prototype");
            foreach (var dialogKvp in dialogNodeMap)
            {
                var dialogNode = LoadDialogNode(cnv, (GomObjectData)dialogKvp.Value);
                cnv.DialogNodes.Add(dialogNode);
                cnv.NodeLookup[dialogNode.NodeId] = dialogNode;
                cnv.QuestStarted.AddRange(dialogNode.QuestsGranted);
                cnv.QuestEnded.AddRange(dialogNode.QuestsEnded);
                cnv.QuestProgressed.AddRange(dialogNode.QuestsProgressed);
            }

            return cnv;
        }

        static Npc CompanionBySimpleNameId(long nameId)
        {
            if (companionShortNameMap.Count == 0)
            {
                var cmpInfo = DataObjectModel.GetObject("chrCompanionInfo_Prototype");
                var chrCompanionSimpleNameToSpec = cmpInfo.Data.Get<Dictionary<object, object>>("chrCompanionSimpleNameToSpec");
                foreach (var kvp in chrCompanionSimpleNameToSpec)
                {
                    var simpleNameId = (long)kvp.Key;
                    Npc npc = NpcLoader.Load((ulong)kvp.Value);
                    companionShortNameMap[simpleNameId] = npc;
                }
            }

            return companionShortNameMap[nameId];
        }

        static DialogNode LoadDialogNode(Conversation cnv, GomObjectData data)
        {
            DialogNode result = new DialogNode();

            result.NodeId = (int)data.Get<long>("cnvNodeNumber");
            result.MinLevel = (int)data.ValueOrDefault<long>("cnvLevelConditionMin", -1);
            result.MaxLevel = (int)data.ValueOrDefault<long>("cnvLevelConditionMax", -1);
            result.IsEmpty = data.ValueOrDefault<bool>("cnvIsEmpty", false);
            result.IsAmbient = data.ValueOrDefault<bool>("cnvIsAmbient", false);
            result.JoinDisabledForHolocom = data.ValueOrDefault<bool>("cnvIsJoinDisabledForHolocom", false);
            result.ChoiceDisabledForHolocom = data.ValueOrDefault<bool>("cnvIsVoteWinDisabledForHolocom", false);
            result.AbortsConversation = data.ValueOrDefault<bool>("cnvAbortConversation", false);
            result.IsPlayerNode = data.ValueOrDefault<bool>("cnvIsPcNode", false);

            result.ActionHook = QuestHookExtensions.ToQuestHook(data.ValueOrDefault<string>("cnvActionHook", null));

            // Load Alignment Results
            long alignmentAmount = data.ValueOrDefault<long>("cnvRewardForceAmount", 0);
            if (alignmentAmount != 0)
            {
                string forceType = data.Get<ScriptEnum>("cnvRewardForceType").ToString();
                result.AlignmentGain = ConversationAlignmentExtensions.ToConversationAlignment(alignmentAmount, forceType);
            }

            // Load Companion Affection Results
            var affectionGains = data.ValueOrDefault<Dictionary<object, object>>("cnvRewardAffectionRewards", null);
            result.AffectionRewards = new Dictionary<Npc, ConversationAffection>();
            if (affectionGains != null)
            {
                foreach (var companionGain in affectionGains)
                {
                    long companionShortNameId = (long)companionGain.Key;
                    ConversationAffection affectionGain = ConversationAffectionExtensions.ToConversationAffection((long)companionGain.Value);
                    Npc companion = CompanionBySimpleNameId(companionShortNameId);
                    result.AffectionRewards[companion] = affectionGain;
                }
            }

            // Get Text
            var textMap = data.Get<Dictionary<object, object>>("locTextRetrieverMap");
            GomObjectData txtData = (GomObjectData)textMap[(long)result.NodeId];
            result.Text = StringTable.TryGetString(cnv.Fqn, txtData);

            result.ChildIds = new List<int>();
            foreach (long childId in data.Get<List<object>>("cnvChildNodes"))
            {
                result.ChildIds.Add((int)childId);
            }

            // Load Quests
            var actionQuest = data.ValueOrDefault<ulong>("cnvActionQuest", 0);
            if (actionQuest > 0)
            {
                result.ActionQuest = QuestLoader.Load(actionQuest);
            }

            var questReward = data.ValueOrDefault<ulong>("cnvRewardQuest", 0);
            if (questReward > 0)
            {
                result.QuestReward = QuestLoader.Load(questReward);
            }

            var questGrants = data.Get<Dictionary<object, object>>("cnvNodeQuestGrants");
            result.QuestsGranted = new List<Quest>();
            foreach (var grant in questGrants)
            {
                if ((bool)grant.Value)
                {
                    Quest q = QuestLoader.Load((ulong)grant.Key);
                    result.QuestsGranted.Add(q);
                }
            }

            var questEnds = data.Get<Dictionary<object, object>>("cnvNodeQuestEnds");
            result.QuestsEnded = new List<Quest>();
            foreach (var ends in questEnds)
            {
                if ((bool)ends.Value)
                {
                    Quest q = QuestLoader.Load((ulong)ends.Key);
                    result.QuestsEnded.Add(q);
                }
            }

            var questProgress = data.Get<Dictionary<object, object>>("cnvNodeQuestProgress");
            result.QuestsProgressed = new List<Quest>();
            foreach (var prog in questProgress)
            {
                if ((bool)prog.Value)
                {
                    Quest q = QuestLoader.Load((ulong)prog.Key);
                    result.QuestsProgressed.Add(q);
                }
            }

            return result;
        }
    }
}
