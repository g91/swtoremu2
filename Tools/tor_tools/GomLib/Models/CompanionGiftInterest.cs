using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class CompanionGiftInterest
    {
        public Companion Companion { get; set; }
        public GiftType GiftType { get; set; }
        public GiftInterest Reaction { get; set; }
        public GiftInterest RomancedReaction { get; set; }
    }
}
