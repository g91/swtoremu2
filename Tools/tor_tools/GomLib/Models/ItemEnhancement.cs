using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    /// <summary>Contains information about default modifications for items - including the slot for the modification, and the item ID of the modification</summary>
    public class ItemEnhancement
    {
        public EnhancementType Slot { get; set; }
        public ulong ModificationId { get; set; }
        public Item Modification { get; set; }

        public override string ToString()
        {
            return string.Format("{0}: [{1}] {2}", Slot, ModificationId, Modification);
        }

        public override int GetHashCode()
        {
            return Slot.GetHashCode() ^ ModificationId.GetHashCode();
        }
    }
}
