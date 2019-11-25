using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using System.Xml.XPath;
using System.Xml;

namespace GomLib.Models
{
    public class Item : GameObject
    {
        public override string ToString()
        {
            return string.Format("{0:000000} {1}: [{2}] {3}",
                Id, Name, ItemLevel, StatModifiers);
        }

        public Item Clone()
        {
            Item clone = this.MemberwiseClone() as Item;
            //
            ItemStatList ar = new ItemStatList();
            foreach (ItemStat istat in this.StatModifiers)
            {
                ar.Add(istat.Clone());
            }
            clone.StatModifiers = ar;
            //
            return clone;
        }

        public ulong NodeId { get; set; }
        public long NameId { get; set; }
        public string Name { get; set; }
        public long DescriptionId { get; set; }
        public string Description { get; set; }
        public int Value { get; set; }
        public int Durability { get; set; }
        public int MaxStack { get; set; }
        public int UniqueLimit { get; set; }
        public WeaponSpec WeaponSpec { get; set; }
        public ArmorSpec ArmorSpec { get; set; }
        public ArmorSpec ShieldSpec { get; set; }
        public ItemBindingRule Binding { get; set; }
        public string Icon { get; set; }
        public ItemQuality Quality { get; set; }
        public int ItemLevel { get; set; }
        public int Rating { get; set; }
        public int CombinedRating { get; set; }
        public int RequiredLevel { get; set; }
        public int CombinedRequiredLevel { get; set; }
        public ItemDamageType DamageType { get; set; }
        public int VendorStackSize { get; set; }
        public bool RequiresAlignment { get; set; }
        public int RequiredAlignmentTier { get; set; }
        public bool RequiredAlignmentInverted { get; set; }
        public bool RequiresSocial { get; set; }
        public int RequiredSocialTier { get; set; }
        public Profession RequiredProfession { get; set; }
        public int RequiredProfessionLevel { get; set; }
        public ProfessionSubtype DisassembleCategory { get; set; }
        public EnhancementCategory EnhancementCategory { get; set; }
        public EnhancementSubCategory EnhancementSubCategory { get; set; }
        public EnhancementType EnhancementType { get; set; }
        public GiftType GiftType { get; set; }
        public GiftRank GiftRank { get; set; }
        // public AuctionCategory AuctionCategory { get; set; }
        public AppearanceColor AppearanceColor { get; set; }
        public ulong EquipAbilityId { get; set; }
        public Ability EquipAbility { get; set; }
        public ulong UseAbilityId { get; set; }
        public Ability UseAbility { get; set; }
        public string ConversationFqn { get; set; }
        public Conversation Conversation { get; set; }
        public long ModifierSpec { get; set; }
        public Schematic Schematic { get; set; }
        public ulong SchematicId { get; set; }
        public string TreasurePackageSpec { get; set; }
        public long TreasurePackageId { get; set; }
        public long MountSpec { get; set; }
        public Gender RequiredGender { get; set; }
        public int RequiredValorRank { get; set; }
        public bool ConsumedOnUse { get; set; }
        public int TypeBitSet { get; set; }
        public bool IsModdable { get; set; }

        public long Field_4000000FAFE42471 { get; set; }

        public ItemCategory Category { get; set; }
        public ItemSubCategory SubCategory { get; set; }

        public ItemStatList StatModifiers { get; set; }
        public ItemStatList CombinedStatModifiers { get; set; }
        public ItemEnhancementList EnhancementSlots { get; set; }
        public ClassSpecList RequiredClasses { get; set; }
        public SlotTypeList Slots { get; set; }

        public void AddStat(ItemStat stat)
        {
            AddStat(stat.Stat, stat.Modifier);
        }

        public void AddStat(Stat stat, int modifier)
        {
            var s = this.CombinedStatModifiers.Where(x => x.Stat == stat).FirstOrDefault();
            if (s != null)
            {
                s.Modifier += modifier;
            }
            else
            {
                this.CombinedStatModifiers.Add(new ItemStat
                {
                    Modifier = modifier,
                    Stat = stat
                });
            }
        }

        public override int GetHashCode()
        {
            int hash = Name.GetHashCode();
            hash ^= Description.GetHashCode();
            hash ^= this.AppearanceColor.GetHashCode();
            hash ^= this.ArmorSpec.GetHashCode();
            hash ^= this.Binding.GetHashCode();
            hash ^= this.Category.GetHashCode();
            hash ^= this.CombinedRating.GetHashCode();
            hash ^= this.CombinedRequiredLevel.GetHashCode();
            hash ^= this.ConsumedOnUse.GetHashCode();
            hash ^= this.DisassembleCategory.GetHashCode();
            hash ^= this.Durability.GetHashCode();
            hash ^= this.EnhancementCategory.GetHashCode();
            hash ^= this.EnhancementSubCategory.GetHashCode();
            hash ^= this.EnhancementType.GetHashCode();
            hash ^= this.EquipAbility.GetHashCode();
            hash ^= this.GiftRank.GetHashCode();
            hash ^= this.GiftType.GetHashCode();
            hash ^= this.Icon.GetHashCode();
            hash ^= this.IsModdable.GetHashCode();
            hash ^= this.ItemLevel.GetHashCode();
            hash ^= this.MaxStack.GetHashCode();
            hash ^= this.ModifierSpec.GetHashCode();
            hash ^= this.MountSpec.GetHashCode();
            hash ^= this.Quality.GetHashCode();
            hash ^= this.Rating.GetHashCode();
            hash ^= this.RequiredAlignmentInverted.GetHashCode();
            hash ^= this.RequiredAlignmentTier.GetHashCode();
            hash ^= this.RequiredGender.GetHashCode();
            hash ^= this.RequiredLevel.GetHashCode();
            hash ^= this.RequiredProfession.GetHashCode();
            hash ^= this.RequiredProfessionLevel.GetHashCode();
            hash ^= this.RequiredSocialTier.GetHashCode();
            hash ^= this.RequiredValorRank.GetHashCode();
            hash ^= this.RequiresAlignment.GetHashCode();
            hash ^= this.RequiresSocial.GetHashCode();
            hash ^= this.SchematicId.GetHashCode();
            hash ^= this.ShieldSpec.GetHashCode();
            hash ^= this.SubCategory.GetHashCode();
            hash ^= this.TypeBitSet.GetHashCode();
            hash ^= this.UniqueLimit.GetHashCode();
            hash ^= this.UseAbility.GetHashCode();
            hash ^= this.Value.GetHashCode();
            hash ^= this.VendorStackSize.GetHashCode();
            hash ^= this.WeaponSpec.GetHashCode();
            foreach (var x in this.CombinedStatModifiers) { hash ^= x.GetHashCode(); }
            foreach (var x in this.EnhancementSlots) { hash ^= x.GetHashCode(); }
            foreach (var x in this.RequiredClasses) { hash ^= x.Id.GetHashCode(); }
            foreach (var x in this.Slots) { hash ^= x.GetHashCode(); }
            foreach (var x in this.StatModifiers) { hash ^= x.GetHashCode(); }
            return hash;
        }
    }

    public class ItemStatList : List<ItemStat>
    {
        public ItemStatList() : base() { }
        public ItemStatList(IEnumerable<ItemStat> collection) : base(collection) { }
        public override string ToString()
        {
            if (this == null) { return "null"; }
            if (this.Count <= 0) { return "Empty List"; }
            string retVal = "";
            foreach (ItemStat i in this) { retVal += string.Format("{0}, ", i); }
            return retVal;
        }
    }
    public class ItemEnhancementList : List<ItemEnhancement>
    {
        public ItemEnhancementList() : base() { }
        public ItemEnhancementList(IEnumerable<ItemEnhancement> collection) : base(collection) { }
        public override string ToString()
        {
            if (this == null) { return "null"; }
            if (this.Count <= 0) { return "Empty List"; }
            string retVal = "";
            foreach (ItemEnhancement i in this) { retVal += string.Format("{0}, ", i); }
            return retVal;
        }
    }
    public class ClassSpecList : List<ClassSpec>
    {
        public ClassSpecList() : base() { }
        public ClassSpecList(IEnumerable<ClassSpec> collection) : base(collection) { }
        public override string ToString()
        {
            if (this == null) { return "null"; }
            if (this.Count <= 0) { return "Empty List"; }
            string retVal = "";
            foreach (ClassSpec i in this) { retVal += string.Format("{0}, ", i); }
            return retVal;
        }
    }
    public class SlotTypeList : List<SlotType>
    {
        public SlotTypeList() : base() { }
        public SlotTypeList(IEnumerable<SlotType> collection) : base(collection) { }
        public override string ToString()
        {
            if (this == null) { return "null"; }
            if (this.Count <= 0) { return "Empty List"; }
            string retVal = "";
            foreach (SlotType i in this) { retVal += string.Format("{0}, ", i); }
            return retVal;
        }
    }
}
