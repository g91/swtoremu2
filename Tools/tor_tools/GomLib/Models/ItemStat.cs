using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    /// <summary>Contains a Stat modification for an item</summary>
    public class ItemStat
    {
        public ItemStat Clone()
        {
            ItemStat clone = this.MemberwiseClone() as ItemStat;
            //
            //
            return clone;
        }

        public Stat Stat { get; set; }
        public int Modifier { get; set; }

        public override string ToString()
        {
            return string.Format("{0}: {1:#,##0.##}", Stat, Modifier);
        }

        public override int GetHashCode()
        {
            return Stat.GetHashCode() ^ Modifier.GetHashCode();
        }
    }
}
