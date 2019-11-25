using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace GomLib.Models
{
    public class Quest : GameObject
    {
        internal Dictionary<object,object> TextLookup { get; set; }

        public ulong NodeId { get; set; }
        public string Name { get; set; }
        public string Icon { get; set; }
        public bool IsRepeatable { get; set; }
        public int RequiredLevel { get; set; }
        public int XpLevel { get; set; }
        public QuestDifficulty Difficulty { get; set; }
        public bool CanAbandon { get; set; }
        public bool IsHidden { get; set; }
        public bool IsClassQuest { get; set; }
        public bool IsBonus { get; set; }
        public bool BonusShareable { get; set; }
        public long CategoryId { get; set; }
        public QuestCategory Category { get; set; }

        public List<QuestBranch> Branches { get; set; }

        public List<Item> Items { get; set; }
        public List<ClassSpec> Classes { get; set; }

        public override int GetHashCode()
        {
            int hash = Name.GetHashCode();
            if (Icon != null) { hash ^= Icon.GetHashCode(); }
            hash ^= IsRepeatable.GetHashCode();
            hash ^= RequiredLevel.GetHashCode();
            hash ^= XpLevel.GetHashCode();
            hash ^= Difficulty.GetHashCode();
            hash ^= CanAbandon.GetHashCode();
            hash ^= IsHidden.GetHashCode();
            hash ^= IsClassQuest.GetHashCode();
            hash ^= IsBonus.GetHashCode();
            hash ^= BonusShareable.GetHashCode();
            hash ^= Category.GetHashCode();
            foreach (var x in Branches) { hash ^= x.GetHashCode(); }
            foreach (var x in Classes) { hash ^= x.Id.GetHashCode(); }
            return hash;
        }
    }
}
