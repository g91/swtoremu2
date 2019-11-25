using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class CompanionAffectionRank
    {
        public Companion Companion { get; set; }
        public int Rank { get; set; }
        public int Affection { get; set; }
    }
}
