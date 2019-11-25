using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace GomLib.Models
{
    public class QuestBranch
    {
        public int Id { get; set; }
        public int DbId { get; set; }
        public Quest Quest { get; set; }

        public List<QuestStep> Steps { get; set; }

        public List<Item> RewardAll { get; set; }
        public List<Item> RewardOne { get; set; }

        public override int GetHashCode()
        {
            int hash = Id.GetHashCode();
            foreach (var x in Steps) { hash ^= x.GetHashCode(); }
            return hash;
        }
    }
}
