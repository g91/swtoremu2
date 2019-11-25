using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class PackageAbility
    {
        public PackageAbility()
        {
            Levels = new List<int>();
        }

        public ulong PackageId { get; set; }
        public Ability Ability { get; set; }
        public ulong AbilityId { get; set; }
        // public int Rank { get; set; }
        public List<int> Levels { get; set; }
        public bool Scales { get; set; }
        public int Level { get; set; }
        public bool AutoAcquire { get; set; }
        // public int Toughness { get; set; }
        public int CategoryNameId { get; set; }
        public string CategoryName { get; set; }
        // public bool IsTalent { get; set; }

        //public PackageAbility Clone()
        //{
        //    return new PackageAbility()
        //    {
        //        PackageId = this.PackageId,
        //        Ability = this.Ability,
        //        AbilityId = this.AbilityId,
        //        Rank = this.Rank,
        //        Level = this.Level,
        //        AutoAcquire = this.AutoAcquire,
        //        Toughness = this.Toughness,
        //        CategoryName = this.CategoryName,
        //        CategoryNameId = this.CategoryNameId,
        //        IsTalent = this.IsTalent
        //    };
        //}
    }
}
