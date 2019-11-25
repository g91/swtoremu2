using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class QuestTask
    {
        public QuestStep Step { get; set; }
        public int Id { get; set; }
        public int DbId { get; set; }

        public string String { get; set; }
        public QuestHook Hook { get; set; }

        public bool ShowTracking { get; set; }
        public bool ShowCount { get; set; }
        public int CountMax { get; set; }

        public List<Quest> TaskQuests { get; set; }
        public List<Npc> TaskNpcs { get; set; }

        public override int GetHashCode()
        {
            int hash = Id.GetHashCode();
            if (String != null) { hash ^= String.GetHashCode(); }
            hash ^= Hook.GetHashCode();
            hash ^= ShowTracking.GetHashCode();
            hash ^= ShowCount.GetHashCode();
            hash ^= CountMax.GetHashCode();
            return hash;
        }
    }
}
