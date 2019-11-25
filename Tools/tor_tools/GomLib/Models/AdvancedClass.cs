using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class AdvancedClass
    {
        public int Id { get; set; }
        public ulong NodeId { get; set; }
        public string Fqn { get; set; }
        public ClassSpec ClassSpec { get; set; }
        public string Name { get; set; }
        public long NameId { get; set; }
        public List<AbilityPackage> Packages { get; set; }

        public override int GetHashCode()
        {
            int hash = this.Name.GetHashCode();
            hash ^= this.ClassSpec.Id.GetHashCode();
            return hash;
        }
    }
}
