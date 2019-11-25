using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using System.Xml;

namespace GomLib.Models
{
    public class Npc : GameObject
    {
        public ulong NodeId { get; set; }
        public string Name { get; set; }
        public string Title { get; set; }
        public ClassSpec ClassSpec { get; set; }
        public int MinLevel { get; set; }
        public int MaxLevel { get; set; }
        public Faction Faction { get; set; }
        public Toughness Toughness { get; set; }
        public int DifficultyFlags { get; set; }
        public Conversation Conversation { get; set; }
        public string ConversationFqn { get; set; }
        public Codex Codex { get; set; }
        public Profession ProfessionTrained { get; set; }
        public Npc CompanionOverride { get; set; }
        public long LootTableId { get; set; }

        public bool IsClassTrainer { get; set; }
        public bool IsVendor { get { return this.VendorPackages.Count > 0; } }
        public List<string> VendorPackages { get; set; }

        public Npc()
        {
            VendorPackages = new List<string>();
        }

        //public List<string> AbilityPackagesTrained { get; set; }

        public override int GetHashCode()
        {
            int hash = Name.GetHashCode();
            if (Title != null) { hash ^= Title.GetHashCode(); }
            hash ^= ClassSpec.Id.GetHashCode();
            hash ^= MinLevel.GetHashCode();
            hash ^= MaxLevel.GetHashCode();
            hash ^= Faction.GetHashCode();
            hash ^= Toughness.GetHashCode();
            hash ^= DifficultyFlags.GetHashCode();
            if (Codex != null) hash ^= Codex.Id.GetHashCode();
            hash ^= ProfessionTrained.GetHashCode();
            if (ConversationFqn != null) hash ^= ConversationFqn.GetHashCode();
            return hash;
        }
    }
}
