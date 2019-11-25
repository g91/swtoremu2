using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class DialogNode
    {
        public Conversation Conversation { get; set; }
        public int NodeId { get; set; }

        public List<Quest> QuestsGranted { get; set; }
        public List<Quest> QuestsEnded { get; set; }
        public List<Quest> QuestsProgressed { get; set; }
        public Quest QuestReward { get; set; }

        public Quest ActionQuest { get; set; }
        public QuestHook ActionHook { get; set; }

        public int MinLevel { get; set; }
        public int MaxLevel { get; set; }
        public ConversationAlignment AlignmentGain { get; set; }
        public int CreditsGained { get; set; }
        public bool IsEmpty { get; set; }
        public bool JoinDisabledForHolocom { get; set; }
        public bool ChoiceDisabledForHolocom { get; set; }
        public bool AbortsConversation { get; set; }
        public bool IsPlayerNode { get; set; }

        public string Text { get; set; }

        public Dictionary<Npc, ConversationAffection> AffectionRewards { get; set; }

        /// <summary>Doesn't trigger conversation mode - just speaks dialog and prints text to chat tab</summary>
        public bool IsAmbient { get; set; }

        public List<int> ChildIds { get; set; }
        public List<DialogNode> ChildNodes { get; set; }
    }
}
