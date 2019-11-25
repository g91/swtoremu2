using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using System.Xml.XPath;
using System.Text.RegularExpressions;
using System.Xml;

namespace GomLib.Models
{
    public class Ability : GameObject
    {
        public ulong NodeId { get; set; }
        public string Name { get; set; }
        public long NameId { get; set; }
        public string Description { get; set; }
        public long DescriptionId { get; set; }
        public int Level { get; set; }
        public string Icon { get; set; }
        public bool IsHidden { get; set; }
        public bool IsPassive { get; set; }
        public int Version { get; set; }
        public float Cooldown { get; set; }
        public float CastingTime { get; set; }
        public float ChannelingTime { get; set; }
        public float ForceCost { get; set; }
        public float EnergyCost { get; set; }
        public float ApCost { get; set; }
        public ApType ApType { get; set; }
        public float MinRange { get; set; }
        public float MaxRange { get; set; }
        public float GCD { get; set; }
        public bool GcdOverride { get; set; }
        public long ModalGroup { get; set; }
        public ulong SharedCooldown { get; set; }
        public string TalentTokens { get; set; }
        public string AbilityTokens { get; set; }
        public float TargetArc { get; set; }
        public float TargetArcOffset { get; set; }
        public TargetRule TargetRule { get; set; }
        public bool LineOfSightCheck { get; set; }
        public bool Pushback { get; set; }
        public bool IgnoreAlacrity { get; set; }

        public override int GetHashCode()
        {
            int hash = Level.GetHashCode();
            if (Description != null) { hash ^= Description.GetHashCode(); }
            if (Name != null) { hash ^= Name.GetHashCode(); }
            if (Icon != null) { hash ^= Icon.GetHashCode(); }
            hash ^= IsHidden.GetHashCode();
            hash ^= IsPassive.GetHashCode();
            hash ^= Cooldown.GetHashCode();
            hash ^= CastingTime.GetHashCode();
            hash ^= ChannelingTime.GetHashCode();
            hash ^= ForceCost.GetHashCode();
            hash ^= EnergyCost.GetHashCode();
            hash ^= ApCost.GetHashCode();
            hash ^= ApType.GetHashCode();
            hash ^= MinRange.GetHashCode();
            hash ^= MaxRange.GetHashCode();
            hash ^= GCD.GetHashCode();
            hash ^= GcdOverride.GetHashCode();
            if (AbilityTokens != null) { hash ^= AbilityTokens.GetHashCode(); }
            hash ^= TargetArc.GetHashCode();
            hash ^= TargetArcOffset.GetHashCode();
            hash ^= TargetRule.GetHashCode();
            hash ^= LineOfSightCheck.GetHashCode();
            hash ^= Pushback.GetHashCode();
            hash ^= IgnoreAlacrity.GetHashCode();
            return hash;
        }

        public override string ToString()
        {
            return string.Format("{0} {1} {2}", NameId, Name, Description);
        }
    }
}
