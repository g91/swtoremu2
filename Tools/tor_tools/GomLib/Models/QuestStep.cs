using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class QuestStep
    {
        public QuestBranch Branch { get; set; }
        public int Id { get; set; }
        public int DbId { get; set; }
        public bool IsShareable { get; set; }
        public string JournalText { get; set; }

        public List<QuestTask> Tasks { get; set; }
        //public List<string> Strings { get; set; }

        public override int GetHashCode()
        {
            int hash = Id.GetHashCode();
            hash ^= IsShareable.GetHashCode();
            if (JournalText != null) { hash ^= JournalText.GetHashCode(); }
            foreach (var x in Tasks) { hash ^= x.GetHashCode(); }
            return hash;
        }
    }
}
