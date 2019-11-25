using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using Hero;
using Hero.Definition;
using Hero.Types;
using System.Threading;
using ICSharpCode.SharpZipLib.Zip.Compression;
using System.IO;

namespace tor_tools
{
    public partial class dumper : Form
    {
        public dumper()
        {
            InitializeComponent();
        }

        static string extractBasePath = "assets";
        static Repository repository = Repository.Instance;
        static Repository.RepoDirectory rootDirectory = new Repository.RepoDirectory();
        static GOM gom = GOM.Instance;

        static public Dictionary<ulong, HeroDefinition> definitions = new Dictionary<ulong, HeroDefinition>();
        static public Dictionary<HeroDefinition.Types, Dictionary<string, HeroDefinition>> DefinitionsByName = new Dictionary<HeroDefinition.Types, Dictionary<string, HeroDefinition>>();
        static public GOMFolder root;
        static public Dictionary<IDSpaces, IDSpace> spaces;

        private void dumper_Load(object sender, EventArgs e)
        {
            
        }

        private void button1_Click(object sender, EventArgs e)
        {
            ExtractTOR("all"); 
        }

        private void ExtractTOR(string info)
        {
            repository.Initialize(textBox1.Text);

            if (info == "global" || info == "all")
            {
                listBox1.Items.Add("Extract global.dep form Tor Files");
                //resources
                ExtractFile(repository.GetFileInfo("/resources/global.dep"));
            }

            if (info == "systemgenerated" || info == "all")
            {
                listBox1.Items.Add("Extract systemgenerated form Tor Files");
                //systemgenerated
                ExtractFile(repository.GetFileInfo("/resources/systemgenerated/client.gom"));
                ExtractFile(repository.GetFileInfo("/resources/systemgenerated/prototypes.info"));
                ExtractFile(repository.GetFileInfo("/resources/systemgenerated/scriptDef.list"));
                ExtractFile(repository.GetFileInfo("/resources/systemgenerated/buckets.info"));
            }

            if (info == "server" || info == "all")
            {
                listBox1.Items.Add("Extract server form Tor Files");
                //server
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/bfa_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/bfb_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/bfn_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/bfs_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/bma_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/bmf_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/bmn_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/bms_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/chevin_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/colicoid_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/dwarf_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/eshka_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/geonosian_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/hutt_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/hutt_hutt_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/huttsit_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/ithorian_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/ortolan_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/facefx/rakghoul_base.fxa"));
                ExtractFile(repository.GetFileInfo("/resources/server/tbl/chrbackground.tbl"));
                ExtractFile(repository.GetFileInfo("/resources/server/tbl/chrspec.tbl"));
                ExtractFile(repository.GetFileInfo("/resources/server/tbl/fxhuecolors.tbl"));
                ExtractFile(repository.GetFileInfo("/resources/server/tbl/fxusedbyscript.tbl"));
            }

            if (info == "art" || info == "all")
            {
                listBox1.Items.Add("Extract art form Tor Files");
                //art
                ExtractFile(repository.GetFileInfo("/resources/art/environmentmaps/coruscant_main/black_sun_exterior.tiny.dds"));
                ExtractFile(repository.GetFileInfo("/resources/art/environmentmaps/ord_resize/ord_area.dds"));
                ExtractFile(repository.GetFileInfo("/resources/art/environmentmaps/tar_main/area.dds"));
                ExtractFile(repository.GetFileInfo("/resources/art/environmentmaps/tar_main/area.tex"));
                ExtractFile(repository.GetFileInfo("/resources/art/environmentmaps/tar_main/area.tiny.dds"));
            }

            if (info == "bnk2" || info == "all")
            {
                listBox1.Items.Add("Extract bnk2 form Tor Files");
                //bnk2
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_act_2_ships_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_act_2_ships_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_balmorra_2_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_balmorra_2_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_corellia_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_corellia_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_coruscant_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_coruscant_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_eternity_vault_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_eternity_vault_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_athiss_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_athiss_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_cademimu_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_cademimu_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_colicoid_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_colicoid_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_crimson_vengeance_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_crimson_vengeance_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_directive_7_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_directive_7_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_ilum_battle_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_ilum_battle_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_ilum_space_station_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_ilum_space_station_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_mandalorian_raiders_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_mandalorian_raiders_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_republic_revan_arc_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_republic_revan_arc_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_republic_spacedock_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_republic_spacedock_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_republic_transition_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_fp_republic_transition_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_general_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_general_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_ilum_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_ilum_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_kaon_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_kaon_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_ord_rak_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_ord_rak_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_rd_hutt_palace_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_rd_hutt_palace_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_taris_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_taris_media.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_voss_data.bnk"));
                ExtractFile(repository.GetFileInfo("/resources/bnk2/location_voss_media.bnk"));
            }

            if (info == "gfx" || info == "all")
            {
                listBox1.Items.Add("Extract gfx form Tor Files");
                //gfx
                ExtractFile(repository.GetFileInfo("/resources/gfx/codex/cdx.achievements.flashpoint.the_eternity_vault.hardmode.disciples.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/codex/cdx.achievements.flashpoint.the_eternity_vault.nightmare.disciples.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a01_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a01_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a01_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a01_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a02_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a02_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a02_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a02_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a03_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a03_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low01_a03_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a01_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a01_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a01_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a01_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a02_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a02_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a02_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a02_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a03_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a03_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low02_a03_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a01_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a01_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a01_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a01_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a02_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a02_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a02_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a02_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a03_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a03_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low03_a03_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a01_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a01_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a01_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a01_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a02_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a02_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a02_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a02_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a03_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a03_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low04_a03_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a01_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a01_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a01_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a01_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a02_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a02_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a02_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a02_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a03_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a03_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low05_a03_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a01_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a01_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a01_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a01_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a02_v01.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a02_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a02_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a02_v04.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a03_v02.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a03_v03.dds"));
                ExtractFile(repository.GetFileInfo("/resources/gfx/icons/rifle_low06_a03_v04.dds"));
            }

            if (info == "en-us/bnk2" || info == "all")
            {
                listBox1.Items.Add("Extract en-us/bnk2 form Tor Files");

                //en-us/bnk2/
                ExtractFile(repository.GetFileInfo("/resources/en-us/bnk2/cnv_misc_generic_lines_jedi_knight_m.acb"));
                ExtractFile(repository.GetFileInfo("/resources/en-us/bnk2/cnv_misc_generic_lines_jedi_wizard_m.acb"));
                ExtractFile(repository.GetFileInfo("/resources/en-us/bnk2/cnv_misc_generic_lines_jedi_wizard_f.acb"));
                ExtractFile(repository.GetFileInfo("/resources/en-us/bnk2/cnv_misc_generic_lines_sith_sorcerer_m.acb"));
                ExtractFile(repository.GetFileInfo("/resources/en-us/bnk2/cnv_misc_generic_lines_sith_warrior_f.acb"));
                ExtractFile(repository.GetFileInfo("/resources/en-us/bnk2/cnv_misc_generic_lines_smuggler_f.acb"));
                ExtractFile(repository.GetFileInfo("/resources/en-us/bnk2/cnv_misc_generic_lines_spy_f.acb"));
                ExtractFile(repository.GetFileInfo("/resources/en-us/bnk2/cnv_misc_generic_lines_trooper_f.acb"));
                ExtractFile(repository.GetFileInfo("/resources/en-us/bnk2/cnv_misc_generic_lines_trooper_m.acb"));
            }


            if (info == "world" || info == "all")
            {
                listBox1.Items.Add("Extract world form Tor Files");

                //world
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686040187270001/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686033020472228/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686021579460422/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686039258170278/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686033507370314/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686035947170168/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686040994970456/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686041464170233/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686041700070232/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686041700070345/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686041748971553/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686041922470000/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686041944170162/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686044023070789/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686023014030644/mapnotes.not"));
                ExtractFile(repository.GetFileInfo("/resources/world/areas/4611686025383332936/mapnotes.not"));
            }

            if (info == "buckets" || info == "all")
            {
                LoadPrototypes(repository.GetFile("/resources/systemgenerated/prototypes.info"));

                for (int i = 0; i < 500; i++)
                {
                    string name = string.Format("/resources/systemgenerated/buckets/{0}.bkt", i);
                    listBox1.Items.Add(string.Format("Extract /resources/systemgenerated/buckets/{0}.bkt form Tor Files", i));

                    ExtractFile(repository.GetFileInfo(name));
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            ExtractTOR("global"); 
        }

        private void button3_Click(object sender, EventArgs e)
        {
            ExtractTOR("systemgenerated");
        }

        private void button4_Click(object sender, EventArgs e)
        {
            ExtractTOR("server"); 
        }

        private void button5_Click(object sender, EventArgs e)
        {
            ExtractTOR("art");
        }

        private void button6_Click(object sender, EventArgs e)
        {
            ExtractTOR("bnk2");
        }

        private void button7_Click(object sender, EventArgs e)
        {
            ExtractTOR("gfx");
        }

        private void button8_Click(object sender, EventArgs e)
        {
            ExtractTOR("en-us/bnk2");
        }

        private void button9_Click(object sender, EventArgs e)
        {
            ExtractTOR("world");
        }

        private void button10_Click(object sender, EventArgs e)
        {
            ExtractTOR("buckets");
        }
        static void AddNode(HeroNodeDef node, TextWriter tw)
        {
            string[] strArray = node.Name.Split(new char[] { '.' });
            if (strArray.Length > 0)
            {
                foreach (string str in strArray)
                {
                    tw.WriteLine(string.Format("CreateFolder: {0}<br>", str));
                    Console.WriteLine(string.Format("CreateFolder: {0}<br>", str));
                }
            }
        }

        static void LoadPrototype(ulong id)
        {
            string name = string.Format("/resources/systemgenerated/prototypes/{0}.node", id);
        }

        static void LoadPrototypes(Stream stream)
        {
            ulong num;
            PackedStream_2 m_ = new PackedStream_2(1, stream);
            m_.CheckResourceHeader(0x464e4950, 1, 1);
            m_.Read(out num);
            for (ulong i = 0L; i < num; i += (ulong)1L)
            {
                ulong num3;
                ulong num4;
                m_.Read(out num3);
                m_.Read(out num4);
                LoadPrototype(num3);
            }
            m_.CheckEnd();
        }

        static void ExtractFile(Repository.RepositoryFileInfo info)
        {
            string str;
            if (info != null)
            {
                Stream file = info.File.GetFile(info);
                if (info.Name != null)
                {
                    str = extractBasePath + info.Name;
                }
                else
                {
                    str = string.Format("{0}/{1:X}.bin", extractBasePath, info.Hash);
                }
                Console.WriteLine("{0}", str);
                str = str.Replace('/', '\\');
                if (info.Name != null)
                {
                    string[] strArray = info.Name.Split(new char[] { '/' });

                    string path = extractBasePath + @"\";
                    for (int i = 1; i < (strArray.Length - 1); i++)
                    {
                        if (rootDirectory.SubDirectories.ContainsKey(strArray[i]))
                        {
                            rootDirectory = rootDirectory.SubDirectories[strArray[i]];
                        }
                        else
                        {
                            Repository.RepoDirectory directory2 = new Repository.RepoDirectory
                            {
                                Name = strArray[i]
                            };
                            rootDirectory.SubDirectories[strArray[i]] = directory2;
                            rootDirectory = directory2;
                        }
                        path = path + strArray[i] + @"\";
                    }
                    if (!rootDirectory.Files.Contains(strArray[strArray.Length - 1]))
                    {
                        rootDirectory.Files.Add(strArray[strArray.Length - 1]);
                    }

                    Directory.CreateDirectory(path);
                }
                Stream stream2 = File.Open(str, FileMode.Create, FileAccess.Write);
                byte[] buffer = new byte[file.Length];
                file.Read(buffer, 0, buffer.Length);
                stream2.Write(buffer, 0, buffer.Length);
                file.Close();
                stream2.Close();
            }
        }
    }
}
