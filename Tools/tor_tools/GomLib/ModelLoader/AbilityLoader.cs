using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.ModelLoader
{
    public class AbilityLoader : IModelLoader
    {
        const long NameLookupKey = -2761358831308646330;
        const long DescLookupKey = 2806211896052149513;

        static Dictionary<ulong, Ability> idMap = new Dictionary<ulong, Ability>();
        static Dictionary<string, Ability> nameMap = new Dictionary<string, Ability>();

        public string ClassName
        {
            get { return "ablAbility"; }
        }

        public static Models.Ability Load(ulong nodeId)
        {
            Ability result;
            if (idMap.TryGetValue(nodeId, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(nodeId);
            Models.Ability abl = new Ability();
            return Load(abl, obj);
        }

        public static Models.Ability Load(string fqn)
        {
            Ability result;
            if (nameMap.TryGetValue(fqn, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(fqn);
            Models.Ability abl = new Ability();
            return Load(abl, obj);
        }

        public Models.GameObject CreateObject()
        {
            return new Models.Ability();
        }

        /// <summary>Determine the string table to use for an ability given its FQN</summary>
        /// <param name="fqn">FQN of the ability</param>
        /// <returns>Possible string table FQN</returns>
        private static string StringTablePath(string fqn)
        {
            string[] fqnParts = fqn.Split('.');

            // Return str.<first 3 fqn parts>
            int numParts = 3;
            if (fqnParts.Length < 3) { numParts = fqnParts.Length; }
            List<string> resultParts = new List<string>(4);
            resultParts.Add("str");
            for (var i = 0; i < numParts; i++)
            {
                resultParts.Add(fqnParts[i]);
            }

            return String.Join(".", resultParts.ToArray());
        }

        public static Models.Ability Load(Models.Ability abl, GomObject obj)
        {
            if (obj == null) { return abl; }
            if (abl == null) { return null; }

            abl.Fqn = obj.Name;
            abl.NodeId = obj.Id;

            // Ability Info
            abl.IsPassive = obj.Data.ValueOrDefault<bool>("ablIsPassive", false);
            abl.IsHidden = obj.Data.ValueOrDefault<bool>("ablIsHidden", false);
            abl.Icon = obj.Data.ValueOrDefault<string>("ablIconSpec", null);
            TorLib.Icons.Add(abl.Icon);

            var textLookup = obj.Data.Get<Dictionary<object,object>>("locTextRetrieverMap");

            // Load Ability Name
            var nameLookupData = (GomObjectData)textLookup[NameLookupKey];
            abl.NameId = nameLookupData.Get<long>("strLocalizedTextRetrieverStringID");
            abl.Name = StringTable.TryGetString(abl.Fqn, nameLookupData);

            // Load Ability Description
            var descLookupData = (GomObjectData)textLookup[DescLookupKey];
            abl.DescriptionId = descLookupData.Get<long>("strLocalizedTextRetrieverStringID");
            abl.Description = StringTable.TryGetString(abl.Fqn, descLookupData);

            abl.Id = (ulong)(abl.NameId >> 32);

            List<object> abilityEffectList = obj.Data.Get<List<object>>("ablEffectIDs");
            // Load Talent Description Tokens
            if (obj.Data.ContainsKey("ablDescriptionTokens"))
            {
                var tokenList = new List<string>();
                foreach (GomObjectData tokDesc in obj.Data.Get<List<object>>("ablDescriptionTokens"))
                {
                    if (!tokDesc.ContainsKey("ablDescriptionTokenType"))
                    {
                        tokenList.Add(String.Format("rank,{0}", tokDesc.Get<object>("ablDescriptionTokenMultiplier")));
                    }
                    else
                    {
                        string tokType = tokDesc.Get<object>("ablDescriptionTokenType").ToString();
                        switch (tokType)
                        {
                            case "ablDescriptionTokenTypeRank":
                                tokenList.Add(String.Format("rank,{0}", tokDesc.Get<object>("ablDescriptionTokenMultiplier")));
                                break;
                            case "ablDescriptionTokenTypeDamage": {
                                tokenList.AddRange(LoadParamDamage(tokDesc, abilityEffectList));
                                //tokenList.Add("damage");
                                break;
                            }
                            case "ablDescriptionTokenTypeHealing":
                                tokenList.Add(LoadParamHealing(tokDesc, abilityEffectList));
                                //tokenList.Add("healing");
                                break;
                            case "ablDescriptionTokenTypeDuration":
                                tokenList.Add(LoadParamDuration(tokDesc, abilityEffectList));
                                break;
                            case "ablDescriptionTokenTypeBindpoint":
                                tokenList.Add("bindpoint");
                                break;
                        }
                    }
                }

                if (tokenList.Count > 0)
                {
                    abl.TalentTokens = "'" + String.Join("','", tokenList.ToArray()) + "'";
                    abl.AbilityTokens = String.Join(";", tokenList.ToArray());
                }
                else
                {
                    abl.TalentTokens = String.Empty;
                    abl.AbilityTokens = null;
                }
            }

            // Load active ability info (energy cost, range, casting time, etc)
            abl.MinRange = obj.Data.ValueOrDefault<float>("ablMinRange", 0);
            abl.MaxRange = obj.Data.ValueOrDefault<float>("ablMaxRange", 0);
            abl.ApCost = obj.Data.ValueOrDefault<float>("ablActionPointCost", 0);
            abl.EnergyCost = obj.Data.ValueOrDefault<float>("ablEnergyCost", 0);
            abl.ForceCost = obj.Data.ValueOrDefault<float>("ablForceCost", 0);
            abl.ChannelingTime = obj.Data.ValueOrDefault<float>("ablChannelingTime", 0);
            abl.CastingTime = obj.Data.ValueOrDefault<float>("ablCastingTime", 0);
            abl.Cooldown = obj.Data.ValueOrDefault<float>("ablCooldownTime", 0);

            abl.Pushback = obj.Data.ValueOrDefault<bool>("ablUsesSpellPushback", true);
            // abl.ApType
            if (abl.ApCost > 0)
            {
                if (abl.Fqn.StartsWith("abl.jedi_knight"))
                {
                    abl.ApType = ApType.Focus;
                }
                else if (abl.Fqn.StartsWith("abl.trooper"))
                {
                    abl.ApType = ApType.Ammo;
                }
                else if (abl.Fqn.StartsWith("abl.sith_war"))
                {
                    abl.ApType = ApType.Rage;
                }
            }
            else if ((abl.ForceCost == 0) && (abl.EnergyCost == 0) && (abl.Fqn.StartsWith("abl.bounty_hunter.")))
            {
                // Find heat cost
                abl.ApCost = HeatGeneration(abilityEffectList);
                abl.ApType = (abl.ApCost > 0) ? ApType.Heat : ApType.None;
            }
            else
            {
                abl.ApType = ApType.None;
            }

            abl.IgnoreAlacrity = obj.Data.ValueOrDefault<bool>("ablIgnoreAlacrity", false);
            abl.GCD = obj.Data.ValueOrDefault<float>("ablGlobalCooldownTime", -1f);
            abl.GcdOverride = abl.GCD > -0.5f;
            abl.LineOfSightCheck = obj.Data.ValueOrDefault<bool>("ablIsLineOfSightChecked", true);
            abl.ModalGroup = obj.Data.ValueOrDefault<long>("ablModalGroup", 0);

            var sharedCooldowns = (List<object>)obj.Data.ValueOrDefault<List<object>>("ablCooldownTimerSpecs", null);
            if (sharedCooldowns != null)
            {
                if (sharedCooldowns.Count > 1)
                {
                    //Console.WriteLine("{0} has more than 1 shared cooldown? How does this work.", abl.Fqn);
                }
                if (sharedCooldowns.Count > 0)
                {
                    abl.SharedCooldown = (ulong)sharedCooldowns[0];
                }
            }

            abl.TargetArc = obj.Data.ValueOrDefault<float>("ablTargetArc", 0);
            abl.TargetArcOffset = obj.Data.ValueOrDefault<float>("ablTargetArcOffset", 0);
            abl.TargetRule = ((ScriptEnum)obj.Data.ValueOrDefault<ScriptEnum>("ablTargetRule", null)).ToTargetRule();


            return abl;
        }

        public void LoadObject(Models.GameObject loadMe, GomObject obj)
        {
            GomLib.Models.Ability abl = (Models.Ability)loadMe;
            Load(abl, obj);
        }

        private static float HeatGeneration(List<object> effectIds)
        {
            if (effectIds == null) { return 0; }

            foreach (ulong effId in effectIds)
            {
                var eff = DataObjectModel.GetObject(effId);
                if (!String.Equals(eff.Data.ValueOrDefault<ScriptEnum>("effSlotType",null).ToString(), "conSlotEffectOther")) { continue; } // GenerateHeat function only appears in this type of effect
                var subEffects = eff.Data.ValueOrDefault<List<object>>("effSubEffects", null);
                foreach (GomObjectData subEff in subEffects)
                {
                    var effActions = subEff.ValueOrDefault<List<object>>("effActions", null);
                    foreach (GomObjectData effAction in effActions)
                    {
                        if (effAction.ValueOrDefault<ScriptEnum>("effActionName", null).ToString() == "effAction_GenerateHeat")
                        {
                            // Heat = effAction.effFloatParams[effParam_Amount]
                            return (float)((IDictionary<object, object>)effAction.ValueOrDefault<Dictionary<object,object>>("effFloatParams", null)).First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_Amount").Value;
                        }
                    }
                }
            }

            return 0;
        }

        private static bool HasDamageAction(GomObject effect)
        {
            var tokSubEffects = (List<object>)effect.Data.ValueOrDefault<List<object>>("effSubEffects", null);
            foreach (GomObjectData subEff in tokSubEffects)
            {
                foreach (GomObjectData a in subEff.ValueOrDefault<List<object>>("effActions", null))
                {
                    switch (((ScriptEnum)a.ValueOrDefault<ScriptEnum>("effActionName", null)).ToString())
                    {
                        case "effAction_WeaponDamage":
                        case "effAction_SpellDamage":
                            return true;
                    }
                }
            }

            return false;
        }

        private static List<string> LoadParamDamage(GomObjectData tokDesc, List<object> abilityEffectList)
        {
            int tokEffIndex = (int)tokDesc.ValueOrDefault<long>("ablDescriptionTokenEffect", 0);
            int tokSubEffIndex = (int)tokDesc.ValueOrDefault<long>("ablDescriptionTokenSubEffect", 0);
            float multi = (float)tokDesc.ValueOrDefault<float>("ablDescriptionTokenMultiplier", 0f);
            if (!(tokEffIndex < abilityEffectList.Count)) { return new List<string>() { "damage" }; }
            // Effect is in-range, find the coefficients for dmg formula
            GomObject tokEff = null;
            if (tokEffIndex >= 0) {
                tokEff = DataObjectModel.GetObject((ulong)abilityEffectList[tokEffIndex]);
            } else {
                foreach (ulong ablEffId in abilityEffectList) {
                    tokEff = DataObjectModel.GetObject(ablEffId);
                    if (tokEff == null) { continue; }
                    if (HasDamageAction(tokEff)) {
                        break;
                    } else {
                        tokEff = null;
                    }
                }
            }
            if (tokEff == null) { return new List<string>() { "damage" }; }

            var tokSubEffects = (List<object>)tokEff.Data.ValueOrDefault<List<object>>("effSubEffects", null);
            List<GomObjectData> actions = new List<GomObjectData>();
            List<bool> isWeapon = new List<bool>();
            // Loop through subEffects
            if ((tokSubEffIndex >= 0) && (tokSubEffIndex < tokSubEffects.Count)) {
                GomObjectData subEff = (GomObjectData)tokSubEffects[tokSubEffIndex];
                foreach (GomObjectData a in subEff.ValueOrDefault<List<object>>("effActions", null)) {
                    switch (((ScriptEnum)a.ValueOrDefault<ScriptEnum>("effActionName", null)).ToString()) {
                        case "effAction_WeaponDamage": { actions.Add(a); isWeapon.Add(true); break; }
                        case "effAction_SpellDamage": { actions.Add(a); isWeapon.Add(false); break; }
                    }
                }
            } else {
                foreach (GomObjectData subEff in tokSubEffects) {
                    var effActions = (List<object>)subEff.Get<List<object>>("effActions");
                    foreach (GomObjectData a in effActions) {
                        var b = ((ScriptEnum)a.Get<ScriptEnum>("effActionName")).ToString();
                        switch (b) {
                            case "effAction_WeaponDamage": { actions.Add(a); isWeapon.Add(true); break; }
                            case "effAction_SpellDamage": { actions.Add(a); isWeapon.Add(false); break; }
                        }
                    }
                    //if (actions != null) { break; }
                }
            }

            if (actions == null || actions.Count <= 0) { return new List<string>() { "damage" }; }
            var retVal = new List<string>();

            for(int i=0; i < actions.Count;  i++)
            {
                retVal.Add(LoadParamDamageChild(multi, actions[i], isWeapon[i]));
            }

            return retVal;
        }

        private static string LoadParamDamageChild(float multi, GomObjectData action, bool isWeapon)
        {
            var floatParams = (Dictionary<object, object>)action.Get<Dictionary<object,object>>("effFloatParams");
            //
            float flurrMin = floatParams.Keys.Where(i => ((ScriptEnum)i).ToString() == "effParam_FlurryBlowsMin").Count() > 0 ? (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_FlurryBlowsMin").Value : 0f;
            float flurrMax = floatParams.Keys.Where(i => ((ScriptEnum)i).ToString() == "effParam_FlurryBlowsMax").Count() > 0 ? (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_FlurryBlowsMax").Value : 0f;
            float threatPerc = floatParams.Keys.Where(i => ((ScriptEnum)i).ToString() == "effParam_ThreatParam").Count() > 0 ? (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_ThreatParam").Value : 0f;
            float stdHpMin = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_StandardHealthPercentMin").Value;
            float stdHpMax = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_StandardHealthPercentMax").Value;
            float modFMin = floatParams.Keys.Where(i => ((ScriptEnum)i).ToString() == "effParam_AmountModifierFixedMin").Count() > 0 ? (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_AmountModifierFixedMin").Value : 0f;
            float modFMax = floatParams.Keys.Where(i => ((ScriptEnum)i).ToString() == "effParam_AmountModifierFixedMax").Count() > 0 ? (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_AmountModifierFixedMax").Value : 0f;
            float modPct = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_AmountModifierPercent").Value;
            float coeff = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_Coefficient").Value;
            float amtMin = 0; float amtMax = 0; float amtPct = 0;
            if (!isWeapon) {
                amtMin = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_AmountMin").Value;
                amtMax = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_AmountMax").Value;
                amtPct = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_AmountPercent").Value;
            }

            if (amtMin != 0) {
                return String.Format("damage,{0},{1},{2},{3},{4},{5}",
                    flurrMin, flurrMax, threatPerc, multi, amtMin, amtMax);
            } else {
                return String.Format("damage,{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}",
                    flurrMin, flurrMax, threatPerc, isWeapon ? 'w' : 's', multi, coeff, stdHpMin, stdHpMax, modFMin, modFMax, modPct);
            }
        }

        private static string LoadParamHealing(GomObjectData tokDesc, List<object> abilityEffectList)
        {
            int tokEffIndex = (int)tokDesc.ValueOrDefault<long>("ablDescriptionTokenEffect", 0);
            int tokSubEffIndex = (int)tokDesc.ValueOrDefault<long>("ablDescriptionTokenSubEffect", 0);
            float multi = (float)tokDesc.ValueOrDefault<float>("ablDescriptionTokenMultiplier", 0f);

            if (tokEffIndex < abilityEffectList.Count)
            {
                // Effect is in-range, find the coefficients for healing formula
                var tokEff = DataObjectModel.GetObject((ulong)abilityEffectList[tokEffIndex]);
                if (tokEff == null) { return "healing"; }

                var tokSubEffects = (List<object>)tokEff.Data.ValueOrDefault<List<object>>("effSubEffects", null);
                GomObjectData action = null;
                // Loop through subEffects
                if ((tokSubEffIndex >= 0) && (tokSubEffIndex < tokSubEffects.Count))
                {
                    GomObjectData subEff = (GomObjectData)tokSubEffects[tokSubEffIndex];
                    foreach (GomObjectData a in subEff.ValueOrDefault<List<object>>("effActions", null))
                    {
                        if (((ScriptEnum)a.ValueOrDefault<ScriptEnum>("effActionName", null)).ToString() == "effAction_Heal")
                        {
                            action = a;
                            break;
                        }
                    }
                }
                else
                {
                    foreach (GomObjectData subEff in tokSubEffects)
                    {
                        var effActions = (List<object>)subEff.ValueOrDefault<List<object>>("effActions", null);
                        foreach (GomObjectData a in effActions)
                        {
                            if (((ScriptEnum)a.ValueOrDefault<ScriptEnum>("effActionName", null)).ToString() == "effAction_Heal")
                            {
                                action = a;
                                break;
                            }
                        }
                        if (action != null) { break; }
                    }
                }

                if (action == null) { return "healing"; }

                var floatParams = (Dictionary<object, object>)action.ValueOrDefault<Dictionary<object,object>>("effFloatParams", null);
                float amtMin = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_AmountMin").Value;
                float amtMax = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_AmountMax").Value;
                float amtPct = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_AmountPercent").Value;
                float stdHpMin = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_StandardHealthPercentMin").Value;
                float stdHpMax = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_StandardHealthPercentMax").Value;
                float coeff = (float)floatParams.First(kvp => ((ScriptEnum)kvp.Key).ToString() == "effParam_HealingPowerCoefficient").Value;

                if (amtMin != 0)
                {
                    return String.Format("healing,{0},{1},{2}", multi, amtMin, amtMax);
                }
                else {
                    return String.Format("healing,{0},{1},{2},{3}", multi, coeff, stdHpMin, stdHpMax);
                }
            }

            return "healing";
        }

        private static string LoadParamDuration(GomObjectData tokDesc, List<object> abilityEffectList)
        {
            float duration = 1;
            int tokEffIndex = (int)tokDesc.Get<long>("ablDescriptionTokenEffect");
            int tokSubEffIndex = (int)tokDesc.Get<long>("ablDescriptionTokenSubEffect");
            if (tokEffIndex >= abilityEffectList.Count)
            {
                // Effect is out of range, so just put a 0 here for the duration.
                duration = 0;
            }
            else
            {
                var tokEff = DataObjectModel.GetObject((ulong)abilityEffectList[tokEffIndex]);
                if (tokSubEffIndex < 1)
                {
                    duration = (float)((ulong)tokEff.Data.ValueOrDefault<ulong>("effDuration", 0)) / 1000;
                }
                else
                {
                    var tokSubEffInitializers = ((GomObjectData)tokEff.Data.Get<List<object>>("effSubEffects")[tokSubEffIndex - 1]).Get<List<object>>("effInitializers");
                    foreach (GomObjectData effInit in tokSubEffInitializers)
                    {
                        if (effInit.Get<object>("effInitializerName").ToString() == "effInitializer_SetDuration")
                        {
                            var durationMap = effInit.Get<Dictionary<object,object>>("field_40000004E27E11D1");
                            foreach (var durKvp in durationMap)
                            {
                                if (((ScriptEnum)durKvp.Key).Value == 0xA2)
                                {
                                    duration = (float)durKvp.Value / 1000;
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
            }

            return String.Format("duration,{0}", duration);
        }

        public void LoadReferences(Models.GameObject obj, GomObject gom)
        {
            // No references to load
        }
    }
}
