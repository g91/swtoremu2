using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class AbilityPackage
    {
        public AbilityPackage()
        {
            this.PackageAbilities = new List<PackageAbility>();
        }

        public string Id { get; set; }
        public ulong NodeId { get; set; }
        public List<PackageAbility> PackageAbilities { get; private set; }
    }
}
