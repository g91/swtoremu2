using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GomLib.Models;

namespace GomLib.ModelLoader
{
    public class AreaLoader
    {
        static StringTable strTable;

        static AreaLoader()
        {
            strTable = StringTable.Find("str.sys.worldmap");
        }

        public string ClassName
        {
            get { return "mapAreasDataObject"; }
        }

        public static Models.Area Load(Models.Area area, GomObjectData obj)
        {
            if (obj == null) { return area; }
            if (area == null) { return null; }

            IDictionary<string, object> objAsDict = obj.Dictionary;
            if (objAsDict.ContainsKey("mapAreasDataDisplayNameId") && objAsDict.ContainsKey("mapAreasDataDefaultZoneName"))
            {
                area.DisplayNameId = obj.ValueOrDefault<long>("mapAreasDataDisplayNameId", 0);
                area.Id = (int)(area.DisplayNameId & 0x7FFFFFFF);
                area.CommentableId = Guid.NewGuid();
                area.Name = strTable.GetText(area.DisplayNameId, "MapArea." + area.DisplayNameId);
                area.AreaId = obj.ValueOrDefault<ulong>("mapAreasDataAreaId", 0);
                area.ZoneName = obj.ValueOrDefault<string>("mapAreasDataDefaultZoneName", null);

                string mapDataPath = String.Format("world.areas.{0}.mapdata", area.AreaId);
                var mapDataObj = DataObjectModel.GetObject(mapDataPath);
                if (mapDataObj != null)
                {
                    LoadMapdata(area, mapDataObj);
                }
                else
                {
                    Console.WriteLine("No MapData for " + area.Name);
                    area.Id = 0;
                }
            }
            else
            {
                area.Id = 0;
            }

            return area;
        }

        private static void LoadMapdata(Models.Area area, GomObject obj)
        {
            List<object> mapPages = (List<object>)obj.Data.ValueOrDefault<List<object>>("mapDataContainerMapDataList", null);
            Dictionary<long, MapPage> pageLookup = new Dictionary<long, MapPage>();

            if (mapPages != null)
            {
                area.MapPages = new List<MapPage>();
                foreach (GomObjectData mapPage in mapPages)
                {
                    MapPage page = new MapPage();
                    page.Area = area;
                    page.Guid = mapPage.ValueOrDefault<long>("mapPageGUID", 0);
                    page.Id = (int)(page.Guid & 0x7FFFFFFF);
                    var minCoord = mapPage.ValueOrDefault<List<float>>("mapPageMinCoord", null);
                    if (minCoord != null)
                    {
                        page.MinX = minCoord[0];
                        page.MinY = minCoord[1];
                        page.MinZ = minCoord[2];
                    }
                    var maxCoord = mapPage.ValueOrDefault<List<float>>("mapPageMaxCoord", null);
                    if (maxCoord != null)
                    {
                        page.MaxX = maxCoord[0];
                        page.MaxY = maxCoord[1];
                        page.MaxZ = maxCoord[2];
                    }
                    var miniMinCoord = mapPage.ValueOrDefault<List<float>>("mapPageMiniMinCoord", null);
                    if (miniMinCoord != null)
                    {
                        page.MiniMapMinX = miniMinCoord[0];
                        page.MiniMapMinZ = miniMinCoord[2];
                    }
                    var miniMaxCoord = mapPage.ValueOrDefault<List<float>>("mapPageMiniMaxCoord", null);
                    if (miniMaxCoord != null)
                    {
                        page.MiniMapMaxX = miniMaxCoord[0];
                        page.MiniMapMaxZ = miniMaxCoord[2];
                    }
                    page.CalculateVolume();
                    page.MountAllowed = mapPage.ValueOrDefault<bool>("mapMountAllowed", false);
                    page.IsHeroic = mapPage.ValueOrDefault<bool>("mapIsHeroic", false);
                    page.ParentId = mapPage.ValueOrDefault<long>("mapParentNameSId", 0);
                    page.SId = mapPage.ValueOrDefault<long>("mapNameSId", 0);
                    page.MapName = mapPage.ValueOrDefault<string>("mapName", null);

                    string mapImagePath = String.Format("/resources/world/areas/{0}/{1}_r.dds", area.AreaId, page.MapName);
                    page.HasImage = TorLib.Assets.HasFile(mapImagePath);

                    TorLib.Icons.AddMap(area.AreaId, page.MapName);

                    page.Name = strTable.GetText(page.Guid, "MapPage." + page.MapName);
                    pageLookup[page.SId] = page;
                    area.MapPages.Add(page);
                }

                foreach (var p in area.MapPages)
                {
                    if (p.ParentId == 0) continue; // MapPage has no parent (this is a world map)

                    MapPage parent;
                    if (pageLookup.TryGetValue(p.ParentId, out parent))
                    {
                        p.Parent = parent;
                    }
                    else
                    {
                        throw new InvalidOperationException("Unable to find parent map page");
                    }
                }
            }
        }

        public static void LoadReferences(Models.GameObject obj, GomObject gom)
        {
            // No references to load
        }
    }
}
