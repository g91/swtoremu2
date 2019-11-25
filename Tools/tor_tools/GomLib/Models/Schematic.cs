using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GomLib.Models
{
    public class Schematic : GameObject
    {
        public Schematic Clone()
        {
            Schematic clone = this.MemberwiseClone() as Schematic;
            //
            if (this.Item != null) { clone.Item = this.Item.Clone(); }
            if (this.Mat1 != null) { clone.Mat1 = this.Mat1.Clone(); }
            if (this.Mat2 != null) { clone.Mat2 = this.Mat2.Clone(); }
            if (this.Mat3 != null) { clone.Mat3 = this.Mat3.Clone(); }
            if (this.Mat4 != null) { clone.Mat4 = this.Mat4.Clone(); }
            if (this.Mat5 != null) { clone.Mat5 = this.Mat5.Clone(); }
            if (this.Research1 != null) { clone.Research1 = this.Research1.Clone(); }
            if (this.Research2 != null) { clone.Research2 = this.Research2.Clone(); }
            if (this.Research3 != null) { clone.Research3 = this.Research3.Clone(); }
            //
            return clone;
        }

        public ulong NodeId { get; set; }
        public ulong NameId { get; set; }
        public string Name { get { return _name ?? (_name = ""); } set { if (_name != value) { _name = value; } } }
        private string _name;
        public Profession CrewSkillId { get; set; }
        public Item Item { get; set; }
        public int SkillOrange { get; set; }
        public int SkillYellow { get; set; }
        public int SkillGreen { get; set; }
        public int SkillGrey { get; set; }

        public ulong ItemId { get; set; }
        public ulong ItemParentId { get; set; }

        public Item Mat1 { get; set; }
        public int Mat1Quantity { get; set; }
        public Item Mat2 { get; set; }
        public int Mat2Quantity { get; set; }
        public Item Mat3 { get; set; }
        public int Mat3Quantity { get; set; }
        public Item Mat4 { get; set; }
        public int Mat4Quantity { get; set; }
        public Item Mat5 { get; set; }
        public int Mat5Quantity { get; set; }
        public int CraftingTime { get; set; }
        public int CraftingTimeT1 { get; set; }
        public int CraftingTimeT2 { get; set; }
        public int CraftingTimeT3 { get; set; }

        public Workstation Workstation { get; set; }
        public ProfessionSubtype Subtype { get; set; }

        public Item Research1 { get; set; }
        public int ResearchQuantity1 { get; set; }
        public SchematicResearchChance ResearchChance1 { get; set; }
        public Item Research2 { get; set; }
        public int ResearchQuantity2 { get; set; }
        public SchematicResearchChance ResearchChance2 { get; set; }
        public Item Research3 { get; set; }
        public int ResearchQuantity3 { get; set; }
        public SchematicResearchChance ResearchChance3 { get; set; }

        public int MissionCost { get; set; }
        public int MissionDescriptionId { get; set; }
        public string MissionDescription { get; set; }
        public bool MissionUnlockable { get; set; }
        public int MissionLight { get; set; }
        public int MissionLightCrit { get; set; }
        public int MissionDark { get; set; }
        public int MissionDarkCrit { get; set; }
        public int TrainingCost { get; set; }
        public bool DisableDisassemble { get; set; }
        public bool DisableCritical { get; set; }
        public Faction MissionFaction { get; set; }
        public int MissionYieldDescriptionId { get; set; }
        public string MissionYieldDescription { get; set; }
        public bool Deprecated { get; set; }

        public override int GetHashCode()
        {
            int hash = Name.GetHashCode();
            if (Item != null)
            {
                hash ^= Item.GetHashCode();
            }
            hash ^= CrewSkillId.GetHashCode();
            hash ^= SkillOrange.GetHashCode();
            hash ^= SkillYellow.GetHashCode();
            hash ^= SkillGreen.GetHashCode();
            hash ^= SkillGrey.GetHashCode();
            if (Mat1 != null)
            {
                hash ^= Mat1.GetHashCode();
                hash ^= Mat1Quantity;
            }
            if (Mat2 != null)
            {
                hash ^= Mat2.GetHashCode();
                hash ^= Mat2Quantity.GetHashCode();
            }
            if (Mat3 != null)
            {
                hash ^= Mat3.GetHashCode();
                hash ^= Mat3Quantity.GetHashCode();
            }
            if (Mat4 != null)
            {
                hash ^= Mat4.GetHashCode();
                hash ^= Mat4Quantity.GetHashCode();
            }
            if (Mat5 != null)
            {
                hash ^= Mat5.GetHashCode();
                hash ^= Mat5Quantity.GetHashCode();
            }
            hash ^= CraftingTime.GetHashCode();
            hash ^= Subtype.GetHashCode();
            if (Research1 != null)
            {
                hash ^= CraftingTimeT1.GetHashCode();
                hash ^= Research1.GetHashCode();
                hash ^= ResearchChance1.GetHashCode();
                hash ^= ResearchQuantity1.GetHashCode();
            }
            if (Research2 != null)
            {
                hash ^= CraftingTimeT2.GetHashCode();
                hash ^= Research2.GetHashCode();
                hash ^= ResearchChance2.GetHashCode();
                hash ^= ResearchQuantity2.GetHashCode();
            }
            if (Research3 != null)
            {
                hash ^= CraftingTimeT3.GetHashCode();
                hash ^= Research3.GetHashCode();
                hash ^= ResearchChance3.GetHashCode();
                hash ^= ResearchQuantity3.GetHashCode();
            }
            hash ^= MissionCost.GetHashCode();
            if (MissionDescription != null)
            {
                hash ^= MissionDescription.GetHashCode();
            }
            hash ^= MissionUnlockable.GetHashCode();
            hash ^= MissionLight.GetHashCode();
            hash ^= MissionLightCrit.GetHashCode();
            hash ^= MissionDark.GetHashCode();
            hash ^= MissionDarkCrit.GetHashCode();
            hash ^= TrainingCost.GetHashCode();
            hash ^= DisableDisassemble.GetHashCode();
            hash ^= DisableCritical.GetHashCode();
            hash ^= MissionFaction.GetHashCode();
            if (MissionYieldDescription != null) hash ^= MissionYieldDescription.GetHashCode();
            hash ^= Deprecated.GetHashCode();
            return hash;
        }
    }
}