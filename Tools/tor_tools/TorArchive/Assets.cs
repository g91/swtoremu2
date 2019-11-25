using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TorLib
{
    public static class Assets
    {
        public static string assetPath = @"C:\Program Files (x86)\Electronic Arts\BioWare\Star Wars - The Old Republic\Assets";

        private static List<Library> libraries;
        private static System.Text.RegularExpressions.Regex fileNameParse = new System.Text.RegularExpressions.Regex("swtor_(?:test_)?(.*)_1");
        //private static readonly string[] libraryNames = {"main","system","locale_en_us"};
        //private static readonly string[] libraryNames = { "main", "system" };

        //private static readonly string[] libraryNames = { "en-us_global", "main_gamedata", "main_gfx", "main_global", "main_systemgenerated_gom", "main_zed", "main_area_alderaan", "main_area_balmorra", "main_area_belsavis", "main_area_corellia", "main_area_coruscant", "main_area_dromund_kaas", "main_area_epsilon", "main_area_hoth", "main_area_hutta", "main_area_ilum", "main_area_korriban", "main_area_misc", "main_area_nar_shaddaa", "main_area_open_worlds", "main_area_ord_mantell", "main_area_quesh", "main_area_raid", "main_area_taris", "main_area_tatooine", "main_area_tython", "main_area_voss", "main_areadat", "main_areadat_epsilon" };

        private static bool Loaded { get; set; }

        private static void Load()
        {
            if (Loaded) return;

            bool isPtr = false;
            Boolean.TryParse(System.Configuration.ConfigurationManager.AppSettings["usePtrData"], out isPtr);
            string language = System.Configuration.ConfigurationManager.AppSettings["language"] ?? "en-us";

            libraries = new List<Library>();
            //foreach (var libName in libraryNames)
            //{
            //    var lib = new Library(libName, assetPath);
            //    libraries.Add(lib);
            //}

            LoadAssetFiles("main", isPtr);
            LoadAssetFiles(language, isPtr);

            Loaded = true;
        }

        private static void LoadAssetFiles(string fileGroup, bool isPtr)
        {
            string searchPattern;
            if (isPtr)
            {
                searchPattern = String.Format("swtor_test_{0}_*_1.tor", fileGroup);
            }
            else
            {
                searchPattern = String.Format("swtor_{0}_*_1.tor", fileGroup);
            }

            var assetFilePaths = System.IO.Directory.GetFiles(assetPath, searchPattern, System.IO.SearchOption.TopDirectoryOnly);

            foreach (var assetFilePath in assetFilePaths)
            {
                var assetFileName = System.IO.Path.GetFileNameWithoutExtension(assetFilePath);
                var match = fileNameParse.Match(assetFileName);
                if (match.Success)
                {
                    string libName = match.Groups[1].Value;
                    var lib = new Library(libName, assetPath);
                    libraries.Add(lib);
                }
            }
        }

        //public static File FindFileByFqn(string fqn, string ext)
        //{
        //    string filePath = String.Format("/resources/server/{0}.{1}", fqn.Replace('.', '/'), ext);
        //    return FindFile(filePath);
        //}

        public static File FindFile(string path)
        {
            if (!Loaded) { Load(); }

            // path = String.Format("/resources{0}", path.Replace('\\', '/'));
            path = path.Replace('\\', '/');

            File result = null;
            foreach (var lib in libraries)
            {
                result = lib.FindFile(path);
                if (result != null)
                {
                    return result;
                }
            }

            return result;
        }

        public static bool HasFile(string path)
        {
            return FindFile(path) != null;
        }
    }
}
