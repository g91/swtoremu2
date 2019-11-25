using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public enum Toughness
    {
        None = 1,
        Weak = 2,
        Standard = 3,
        Strong = 4,
        Boss1 = 5,
        BossRaid = 6,
        Player = 7,
        Companion = 8,
        Boss2 = 9,
        Boss3 = 10,
        Boss4 = 11
    }

    public static class ToughnessExtensions
    {
        public static Toughness ToToughness(this string str)
        {
            if (String.IsNullOrEmpty(str)) { return Toughness.None; }

            switch (str)
            {
                case "cbtToughness_none": return Toughness.None;
                case "cbtToughness_weak": return Toughness.Weak;
                case "cbtToughness_standard": return Toughness.Standard;
                case "cbtToughness_strong": return Toughness.Strong;
                case "cbtToughness_boss_1": return Toughness.Boss1;
                case "cbtToughness_boss_raid": return Toughness.BossRaid;
                case "cbtToughness_player": return Toughness.Player;
                case "cbtToughness_companion": return Toughness.Companion;
                case "cbtToughness_boss_2": return Toughness.Boss2;
                case "cbtToughness_boss_3": return Toughness.Boss3;
                case "cbtToughness_boss_4": return Toughness.Boss4;
                default: throw new InvalidOperationException("Unknown Toughness: " + str);
            }
        }

        public static Toughness ToToughness(int val)
        {
            if ((val > 11) || (val < 1)) throw new InvalidOperationException("Unknown Toughness: " + val);

            return (Toughness)val;
        }

        public static Toughness ToToughness(this ScriptEnum val)
        {
            if (val == null) { return Toughness.None; }
            return ToToughness((int)val.Value);
        }
    }
}
