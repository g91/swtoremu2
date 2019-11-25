using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class ClassSpec
    {
        public int Id { get; set; }
        public string Fqn { get; set; }
        public ulong NodeId { get; set; }
        public int DataHash { get; set; }
        public bool IsPlayerClass { get; set; }
        public string Name { get; set; }
        public long NameId { get; set; }
        public string Icon { get; set; }
        public int AlignmentLight { get; set; }
        public int AlignmentDark { get; set; }
        public ulong AbilityPackageId { get; set; }
        public AbilityPackage AbilityPackage { get; set; }

        //public static List<string> ParseClassList(string str)
        //{
        //    List<string> results = new List<string>();
        //    if (String.IsNullOrEmpty(str)) return results;

        //    var classes = str.Split(',');
        //    foreach (var c in classes)
        //    {
        //        if (!c.StartsWith("class."))
        //        {
        //            Console.WriteLine("Parsed Class List contains something that isn't a class! {0}", c);
        //            continue;
        //        }

        //        results.Add(FqnToId(c.Trim()));
        //    }
        //    return results;
        //}

        //public static string FqnToId(string fqn)
        //{
        //    if (fqn.StartsWith("class.pc."))
        //    {
        //        string classId = fqn.Substring(9);
        //        switch (classId)
        //        {
        //            case "sith_warrior": return "sith-warrior";
        //            case "sith_sorcerer": return "sith-inquisitor";
        //            case "bounty_hunter": return "bounty-hunter";
        //            case "spy": return "imperial-agent";
        //            case "jedi_knight": return "jedi-knight";
        //            case "jedi_wizard": return "jedi-consular";
        //            case "trooper": return "trooper";
        //            case "smuggler": return "smuggler";
        //            case "advanced.marauder": return "marauder";
        //            case "advanced.juggernaut": return "juggernaut";
        //            case "advanced.assassin": return "assassin";
        //            case "advanced.sorcerer": return "sorcerer";
        //            case "advanced.sniper": return "sniper";
        //            case "advanced.operative": return "operative";
        //            case "advanced.mercenary": return "mercenary";
        //            case "advanced.powertech": return "powertech";
        //            case "advanced.guardian": return "guardian";
        //            case "advanced.sentinel": return "sentinel";
        //            case "advanced.force_wizard": return "sage";
        //            case "advanced.shadow": return "shadow";
        //            case "advanced.gunslinger": return "gunslinger";
        //            case "advanced.scoundrel": return "scoundrel";
        //            case "advanced.commando": return "commando";
        //            case "advanced.specialist": return "vanguard";
        //            default: return classId;
        //        }
        //    }

        //    if (fqn.StartsWith("class."))
        //        fqn = fqn.Substring(6);
        //    fqn = fqn.Replace('.', '-');
        //    fqn = fqn.Replace('_', '-');
        //    return fqn;
        //}

        //static string PackageFqnToId(string fqn)
        //{
        //    string id = fqn;
        //    if (fqn.StartsWith("pkg.abilities."))
        //        id = id.Substring(14);
        //    id = id.Replace('.', '-');
        //    id = id.Replace('_', '-');
        //    return id;
        //}

        public override int GetHashCode()
        {
            int hash = this.Name.GetHashCode();
            hash ^= this.AlignmentDark.GetHashCode();
            hash ^= this.AlignmentLight.GetHashCode();
            hash ^= this.AbilityPackageId.GetHashCode();
            if (this.Icon != null)
            {
                hash ^= this.Icon.GetHashCode();
            }
            hash ^= this.Fqn.GetHashCode();
            hash ^= this.NodeId.GetHashCode();
            return hash;
        }
    }
}
