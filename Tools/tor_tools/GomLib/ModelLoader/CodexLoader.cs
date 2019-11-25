using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.ModelLoader
{
    public class CodexLoader
    {
        const long NameLookupKey = -8863348193830878519;
        const long CategoryLookupKey = -367464477071745071;
        const long DescriptionLookupKey = 1078249248256508798;

        static Dictionary<ulong, Codex> idMap = new Dictionary<ulong, Codex>();
        static Dictionary<string, Codex> nameMap = new Dictionary<string, Codex>();

        public string ClassName
        {
            get { return "cdxType"; }
        }

        public static Models.Codex Load(ulong nodeId)
        {
            Codex result;
            if (idMap.TryGetValue(nodeId, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(nodeId);
            Codex cdx = new Codex();
            return Load(cdx, obj);
        }

        public static Models.Codex Load(string fqn)
        {
            Codex result;
            if (nameMap.TryGetValue(fqn, out result))
            {
                return result;
            }

            GomObject obj = DataObjectModel.GetObject(fqn);
            Codex cdx = new Codex();
            return Load(cdx, obj);
        }

        public Models.GameObject CreateObject()
        {
            return new Models.Codex();
        }

        private static string TryGetString(string fqn, GomObjectData textRetriever)
        {
            string locBucket = textRetriever.ValueOrDefault<string>("strLocalizedTextRetrieverBucket", null);
            long strId = textRetriever.ValueOrDefault<long>("strLocalizedTextRetrieverStringID", -1);
            string defaultStr = textRetriever.ValueOrDefault<string>("strLocalizedTextRetrieverDesignModeText", String.Empty);

            if ((locBucket == null) || (strId == -1))
            {
                return defaultStr;
            }

            StringTable strTable = null;
            try
            {
                strTable = StringTable.Find(locBucket);
            }
            catch
            {
                strTable = null;
            }

            if (strTable == null)
            {
                return defaultStr;
            }

            string result = strTable.GetText(strId, fqn);
            return result ?? defaultStr;
        }

        public static Models.Codex Load(Models.Codex cdx, GomObject obj)
        {
            if (obj == null) { return null; }
            if (cdx == null) { return null; }

            cdx.Fqn = obj.Name;
            cdx.NodeId = obj.Id;

            cdx.Image = obj.Data.ValueOrDefault<string>("cdxImage", null);

            TorLib.Icons.AddCodex(cdx.Image);

            var textLookup = obj.Data.ValueOrDefault<Dictionary<object,object>>("locTextRetrieverMap", null);
            var descLookup = (GomObjectData)textLookup[DescriptionLookupKey];
            var titleLookup = (GomObjectData)textLookup[NameLookupKey];
            object categoryLookup;
            if (textLookup.TryGetValue(CategoryLookupKey, out categoryLookup))
            {
                cdx.CategoryId = ((GomObjectData)categoryLookup).ValueOrDefault<long>("strLocalizedTextRetrieverStringID", 0);
            }

            var titleId = titleLookup.ValueOrDefault<long>("strLocalizedTextRetrieverStringID", 0);
            cdx.Id = (ulong)(titleId >> 32);

            cdx.Title = TryGetString(cdx.Fqn, titleLookup);
            cdx.Text = TryGetString(cdx.Fqn, descLookup);
            cdx.Level = (int)obj.Data.ValueOrDefault<long>("cdxLevel", 0);
            if (String.IsNullOrEmpty(cdx.Title)) { cdx.IsHidden = true; }

            cdx.Faction = FactionExtensions.ToFaction((long)obj.Data.ValueOrDefault<long>("cdxFaction", 0));
            cdx.IsPlanet = obj.Data.ValueOrDefault<bool>("cdxIsPlanetCodex", false);

            Dictionary<object,object> classLookup = obj.Data.ValueOrDefault<Dictionary<object, object>>("cdxClassesLookupList", null);
            if (classLookup == null)
            {
                cdx.ClassRestricted = false;
            }
            else
            {
                cdx.ClassRestricted = true;
                cdx.Classes = new List<ClassSpec>();
                foreach (var kvp in classLookup)
                {
                    if ((bool)kvp.Value)
                    {
                        cdx.Classes.Add(ClassSpecLoader.Load((ulong)kvp.Key));
                    }
                }
            }

            List<object> cdxPlanets = obj.Data.ValueOrDefault<List<object>>("cdxPlanets", null);
            if (cdxPlanets != null)
            {
                cdx.HasPlanets = true;
                cdx.Planets = new List<Codex>();
                foreach (var planetId in cdxPlanets)
                {
                    cdx.Planets.Add(CodexLoader.Load((ulong)planetId));
                }
            }

            return cdx;
        }

        public void LoadObject(Models.GameObject loadMe, GomObject obj)
        {
            GomLib.Models.Codex cdx = (Models.Codex)loadMe;
            Load(cdx, obj);
        }

        public void LoadReferences(Models.GameObject obj, GomObject gom)
        {
            // No references to load
        }
    }
}
