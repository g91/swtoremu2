using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.ModelLoader
{
    public class ItemLoader : IModelLoader
    {
        const long NameLookupKey = -2761358831308646330;
        const long DescLookupKey = 2806211896052149513;

        public string ClassName
        {
            get { return "itmItem"; }
        }

        public Models.GameObject CreateObject()
        {
            return new Models.Item();
        }

        public static Item Load(Models.GameObject obj, GomObject gom)
        {
            var itm = (Models.Item)obj;

            itm.NodeId = gom.Id;
            itm.Fqn = gom.Name;
            itm.AppearanceColor = Models.AppearanceColorExtensions.ToAppearanceColor((string)gom.Data.ValueOrDefault<string>("itmEnhancementColor", null));
            itm.ArmorSpec = Models.ArmorSpecExtensions.ToArmorSpec((long)gom.Data.ValueOrDefault<long>("itmArmorSpec", 0));
            itm.Binding = Models.ItemBindingRuleExtensions.ToBindingRule((ScriptEnum)gom.Data.ValueOrDefault<ScriptEnum>("itmBindingRule", null));

            itm.CombinedStatModifiers = new ItemStatList();
            itm.ConsumedOnUse = (bool)gom.Data.ValueOrDefault<bool>("itmConsumedOnUse", false);
            //itm.Conversation
            itm.ConversationFqn = gom.Data.ValueOrDefault<string>("itmConversation", null);

            var descLookup = (GomObjectData)(gom.Data.Get<Dictionary<object, object>>("locTextRetrieverMap")[DescLookupKey]);
            itm.DescriptionId = descLookup.Get<long>("strLocalizedTextRetrieverStringID");
            itm.Description = StringTable.TryGetString(itm.Fqn, descLookup);

            itm.DisassembleCategory = Models.ProfessionSubtypeExtensions.ToProfessionSubtype((ScriptEnum)gom.Data.ValueOrDefault<ScriptEnum>("prfDisassembleCategory", null));
            itm.Durability = (int)gom.Data.ValueOrDefault<long>("itmMaxDurability", 0);
            itm.EnhancementCategory = Models.EnhancementCategoryExtensions.ToEnhancementCategory((ScriptEnum)gom.Data.ValueOrDefault<ScriptEnum>("itmEnhancementCategory", null));
            itm.EnhancementSubCategory = Models.EnhancementSubCategoryExtensions.ToEnhancementSubCategory((ScriptEnum)gom.Data.ValueOrDefault<ScriptEnum>("itmEnhancementSubCategory", null));
            itm.EnhancementType = Models.EnhancementTypeExtensions.ToEnhancementType((long)gom.Data.ValueOrDefault<long>("itmEnhancementType", 0));

            // Enhancement Slots
            itm.EnhancementSlots = new ItemEnhancementList();
            var enhancementSlots = (List<object>)gom.Data.ValueOrDefault<List<object>>("itmEnhancementSlots", null);
            var enhancementDefaults = (List<object>)gom.Data.ValueOrDefault<List<object>>("itmEnhancementDefaults", null);
            if (enhancementSlots != null)
            {
                for (var i = 0; i < 5; i++)
                {
                    long slot = (long)enhancementSlots[i];
                    if (slot == 0) { continue; }

                    ItemEnhancement enh = new ItemEnhancement();
                    enh.Slot = EnhancementTypeExtensions.ToEnhancementType(slot);
                    enh.ModificationId = (ulong)enhancementDefaults[i];
                    if (enh.ModificationId != 0)
                    {
                        enh.Modification = ItemLoader.Load(enh.ModificationId);
                    }

                    // Don't add empty modulator/augment slots to gear since for some reason it seems to be on every damn modifiable item
                    if ((enh.Slot == EnhancementType.Modulator) && (enh.Modification == null))
                    {
                        continue;
                    }

                    itm.EnhancementSlots.Add(enh);
                }
            }

            itm.EquipAbilityId = gom.Data.ValueOrDefault<ulong>("itmEquipAbility", 0);
            itm.EquipAbility = AbilityLoader.Load(itm.EquipAbilityId);

            itm.GiftRank = Models.GiftRankExtensions.ToGiftRank((ScriptEnum)gom.Data.ValueOrDefault<ScriptEnum>("itmGiftAffectionRank", null));
            itm.GiftType = Models.GiftTypeExtensions.ToGiftType((ScriptEnum)gom.Data.ValueOrDefault<ScriptEnum>("itmGiftType", null));
            itm.Icon = gom.Data.ValueOrDefault<string>("itmIcon", String.Empty);
            TorLib.Icons.Add(itm.Icon);

            itm.ItemLevel = (int)gom.Data.ValueOrDefault<long>("itmBaseLevel", 0);
            itm.MaxStack = (int)gom.Data.ValueOrDefault<long>("itmStackMax", 0);
            itm.ModifierSpec = gom.Data.ValueOrDefault<long>("itmModifierSetID", 0);
            itm.MountSpec = gom.Data.ValueOrDefault<long>("itmMountSpec", 0);

            var nameLookup = (GomObjectData)(gom.Data.Get<Dictionary<object,object>>("locTextRetrieverMap")[NameLookupKey]);
            itm.NameId = nameLookup.Get<long>("strLocalizedTextRetrieverStringID");
            itm.Name = StringTable.TryGetString(itm.Fqn, nameLookup);
            if (itm.Name == null) { itm.Name = String.Empty; }
            itm.Id = (ulong)(itm.NameId >> 32);

            itm.Quality = Models.ItemQualityExtensions.ToItemQuality((ScriptEnum)gom.Data.ValueOrDefault<ScriptEnum>("itmBaseQuality", null));
            //if (itm.EnhancementType != EnhancementType.None)
            //{
                itm.Rating = Tables.ItemRating.GetRating(itm.ItemLevel, itm.Quality);
            //}
            //else
            //{
                //itm.Rating = Tables.ItemRating.GetRating(itm.ItemLevel, ItemQuality.Premium);
            //}
            itm.RequiresAlignment = (bool)gom.Data.ValueOrDefault<bool>("itmAlignmentRequired", false);
            itm.RequiredAlignmentTier = (int)gom.Data.ValueOrDefault<long>("itmRequiredAlignmentTier", int.MaxValue);
            itm.RequiredAlignmentInverted = (bool)gom.Data.ValueOrDefault<bool>("itmRequiredAlignmentInverted", false);

            itm.Field_4000000FAFE42471 = gom.Data.ValueOrDefault<long>("field_4000000FAFE42471", 0);

            // Required Classes
            itm.RequiredClasses = new ClassSpecList();
            var classMap = (Dictionary<object, object>)gom.Data.ValueOrDefault<Dictionary<object, object>>("itmRequiredClasses", null);
            if (classMap != null)
            {
                foreach (var kvp in classMap)
                {
                    if ((bool)kvp.Value)
                    {
                        var classSpec = ClassSpecLoader.Load((ulong)kvp.Key);
                        if (classSpec == null) { continue; }
                        itm.RequiredClasses.Add(classSpec);
                    }
                }
            }

            itm.RequiredGender = GenderExtensions.ToGender((ScriptEnum)gom.Data.ValueOrDefault<ScriptEnum>("itmGenderRequired", null));
            itm.RequiredLevel = (int)gom.Data.ValueOrDefault<long>("itmMinimumLevel", 0);
            itm.RequiredProfession = Models.ProfessionExtensions.ToProfession((ScriptEnum)gom.Data.ValueOrDefault<ScriptEnum>("prfProfessionRequired", null));
            itm.RequiredProfessionLevel = (int)gom.Data.ValueOrDefault<long>("prfProfessionLevelRequired", 0);
            itm.RequiresSocial = (bool)gom.Data.ValueOrDefault<bool>("itmSocialScoreRequired", false);
            itm.RequiredSocialTier = (int)gom.Data.ValueOrDefault<long>("itmRequiredSocialScoreTier", 0);
            itm.RequiredValorRank = (int)gom.Data.ValueOrDefault<long>("itmRequiredValorRank", 0);

            // Item is a recipe/schematic
            GomObjectData schematic = (GomObjectData)gom.Data.ValueOrDefault<object>("prfLearnedSchematic", null);
            if (schematic != null)
            {
                itm.SchematicId = schematic.Get<ulong>("prfSchematicSpecId");
                itm.Schematic = SchematicLoader.Load(itm.SchematicId);
            }

            itm.ShieldSpec = ArmorSpecExtensions.ToArmorSpec((long)gom.Data.ValueOrDefault<long>("itmShieldSpec", 0));

            // Valid Inventory Slots
            itm.Slots = new SlotTypeList();
            var slotList = (List<object>)gom.Data.ValueOrDefault<List<object>>("itmSlotTypes", null);
            if (slotList != null)
            {
                foreach (var slot in slotList)
                {
                    SlotType slotType = SlotTypeExtensions.ToSlotType((ScriptEnum)slot);
                    if (SlotTypeExtensions.IgnoreSlot(slotType)) continue;
                    itm.Slots.Add(slotType);
                }
            }

            // Item Stats
            var stats = (Dictionary<object,object>)gom.Data.ValueOrDefault<Dictionary<object,object>>("itmEquipModStats", null);
            itm.StatModifiers = new ItemStatList();
            if (stats != null)
            {
                foreach (var kvp in stats)
                {
                    ItemStat itmStat = new ItemStat();
                    itmStat.Stat = StatExtensions.ToStat((ScriptEnum)kvp.Key);
                    itmStat.Modifier = (int)(float)kvp.Value;
                    itm.StatModifiers.Add(itmStat);
                }
            }

            // Combined Stats
            itm.CombinedStatModifiers = new ItemStatList();
            itm.CombinedRequiredLevel = itm.RequiredLevel;
            itm.CombinedRating = itm.Rating;
            foreach (var stat in itm.StatModifiers)
            {
                var itmStat = new ItemStat();
                itmStat.Stat = stat.Stat;
                itmStat.Modifier = stat.Modifier;
                itm.CombinedStatModifiers.Add(itmStat);
            }

            foreach (var mod in itm.EnhancementSlots)
            {
                if (mod.Modification != null)
                {
                    if (mod.Slot.IsBaseMod())
                    {
                        if (mod.Modification.RequiredLevel > itm.CombinedRequiredLevel)
                        {
                            itm.CombinedRequiredLevel = mod.Modification.RequiredLevel;
                        }
                        if (mod.Modification.Rating > itm.CombinedRating)
                        {
                            itm.CombinedRating = mod.Modification.Rating;
                        }
                    }

                    foreach (var stat in mod.Modification.CombinedStatModifiers)
                    {
                        ItemStat itmStat = itm.CombinedStatModifiers.FirstOrDefault(s => s.Stat == stat.Stat);
                        if (itmStat == null)
                        {
                            itmStat = new ItemStat();
                            itmStat.Stat = stat.Stat;
                            itmStat.Modifier += stat.Modifier;
                            itm.CombinedStatModifiers.Add(itmStat);
                        }
                        else
                        {
                            itmStat.Modifier += stat.Modifier;
                        }
                    }
                }
            }

            //itm.TreasurePackageSpec;
            itm.TreasurePackageId = (long)gom.Data.ValueOrDefault<long>("field_40000013407C89A3", 0);
            itm.TypeBitSet = (int)(long)gom.Data.ValueOrDefault<long>("itmTypeBitSet", 0);
            itm.UniqueLimit = (int)gom.Data.ValueOrDefault<long>("itmUniqueLimit", 0);

            itm.UseAbilityId = gom.Data.ValueOrDefault<ulong>("itmUsageAbility", 0);
            itm.UseAbility = AbilityLoader.Load(itm.UseAbilityId);

            itm.Value = (int)gom.Data.ValueOrDefault<long>("itmValue", 0);
            itm.VendorStackSize = (int)gom.Data.ValueOrDefault<long>("itmStackVendor", 0);
            itm.WeaponSpec = WeaponSpecExtensions.ToWeaponSpec((ulong)gom.Data.ValueOrDefault<ulong>("cbtWeaponSpec", 0));

            //ulong dmgType = (ulong)gom.Data.ValueOrDefault<ulong>("cbtDamageType", 0);
            //itm.DamageType = ItemDamageTypeExtensions.ToItemDamageType(dmgType);
            switch (itm.WeaponSpec)
            {
                case WeaponSpec.Lightsaber:
                case WeaponSpec.Polesaber:
                case WeaponSpec.Pistol:
                case WeaponSpec.Rifle:
                case WeaponSpec.SniperRifle:
                case WeaponSpec.AssaultCannon:
                    { itm.DamageType = ItemDamageType.Energy; break; }
                case WeaponSpec.Vibroblade:
                case WeaponSpec.VibrobladeTech:
                case WeaponSpec.Vibroknife:
                case WeaponSpec.Shotgun:
                case WeaponSpec.Electrostaff:
                case WeaponSpec.ElectrostaffTech:
                    { itm.DamageType = ItemDamageType.Kinetic; break; }
                default:
                    { itm.DamageType = ItemDamageType.None; break; }
            }

            itm.IsModdable = ((itm.Quality == ItemQuality.Prototype) && (itm.EnhancementSlots.Count > 1)) || itm.Quality == ItemQuality.Moddable;

            ItemSubCategoryExtensions.SetCategory(itm);

            return itm;
        }

        public void LoadReferences(Models.GameObject obj, GomObject gom)
        {
            var itm = (Models.Item)obj;
        }

        public void LoadObject(Models.GameObject obj, GomObject gom)
        {
            Load(obj, gom);
        }

        static Dictionary<ulong, Item> idMap = new Dictionary<ulong, Item>();
        static Dictionary<string, Item> nameMap = new Dictionary<string, Item>();

        public static Models.Item Load(ulong nodeId)
        {
            Item result;
            if (idMap.TryGetValue(nodeId, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(nodeId);
            if (obj == null) { return null; }
            Models.Item itm = new Item();
            return Load(itm, obj);
        }

        public static Models.Item Load(string fqn)
        {
            Item result;
            if (nameMap.TryGetValue(fqn, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(fqn);
            if (obj == null) { return null; }
            Models.Item itm = new Item();
            return Load(itm, obj);
        }
    }
}
