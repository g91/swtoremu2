using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class Codex : GameObject
    {
        public ulong NodeId { get; set; }
        public string Title { get; set; }
        public string Text { get; set; }
        public int Level { get; set; }
        public string Image { get; set; }
        public bool IsHidden { get; set; }

        public long CategoryId { get; set; }
        public Faction Faction { get; set; }
        public List<ClassSpec> Classes { get; set; }
        public bool ClassRestricted { get; set; }

        public bool IsPlanet { get; set; }

        public bool HasPlanets { get; set; }
        public List<Codex> Planets { get; set; }

        public override int GetHashCode()
        {
            int hash = Title.GetHashCode();
            hash ^= Text.GetHashCode();
            hash ^= Level.GetHashCode();
            if (Image != null) { hash ^= Image.GetHashCode(); }
            hash ^= CategoryId.GetHashCode();
            hash ^= Faction.GetHashCode();
            hash ^= IsHidden.GetHashCode();
            if (ClassRestricted) { foreach (var x in Classes) { hash ^= x.Fqn.GetHashCode(); } }
            if (HasPlanets) { foreach (var x in Planets) { hash ^= x.Id.GetHashCode(); } }
            return hash;
        }
    }
}
