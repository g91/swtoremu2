using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class CompanionProfessionModifier
    {
        public Companion Companion { get; set; }
        public Stat Stat { get; set; }
        public int Modifier { get; set; }
    }
}
