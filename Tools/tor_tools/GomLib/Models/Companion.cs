using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class Companion
    {
        public ulong Id { get; set; }
        public string Name { get; set; }
        public string Portrait { get; set; }
        public float ConversationMultiplier { get; set; }
        public Npc Npc { get; set; }
        public List<CompanionProfessionModifier> ProfessionModifiers { get; set; }
        public List<CompanionGiftInterest> GiftInterest { get; set; }
        public List<CompanionAffectionRank> AffectionRanks { get; set; }
        public List<ClassSpec> Classes { get; set; }
        public bool IsRomanceable { get; set; }
    }
}
