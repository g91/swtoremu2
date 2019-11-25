using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net;
using System.Windows;
using System.Threading;
using Microsoft.Win32;
using MySql.Data.MySqlClient;

namespace tor_tools
{
    public partial class Tools : Form
    {
        delegate void SetTextCallback(string text);
        delegate void SetText2Callback(string text);
        delegate void ClearlistCallback();

        static protected MySqlConnection conn;
        static protected MySqlDataReader Reader;

        bool sql = false;

        public Tools()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            listBox1.Items.Add("Geting all the in game Items :)");
            Thread oGetItems = new Thread(new ThreadStart(getItems));
            oGetItems.Start();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            listBox1.Items.Add("Geting all the in game Quest :)");
            Thread oGetItems = new Thread(new ThreadStart(getQuest));
            oGetItems.Start();
        }

        private void button5_Click(object sender, EventArgs e)
        {
            listBox1.Items.Add("Geting all the in game npc's :)");
            Thread oGetItems = new Thread(new ThreadStart(getnpc));
            oGetItems.Start();
        }

        private void button6_Click(object sender, EventArgs e)
        {
            listBox1.Items.Add("Geting Codex list :)");
            Thread oGetItems = new Thread(new ThreadStart(getCodex));
            oGetItems.Start();
        }

        private void Clearlist()
        {
            if (this.listBox1.InvokeRequired)
            {
                ClearlistCallback d = new ClearlistCallback(Clearlist);
                this.Invoke(d, new object[] { });
            }
            else
            {
                this.listBox2.Items.Clear();
            }
        }

        private void addtolist(string text)
        {
            if (this.listBox1.InvokeRequired)
            {
                SetTextCallback d = new SetTextCallback(addtolist);
                this.Invoke(d, new object[] { text });
            }
            else
            {
                this.listBox1.Items.Add(text);
            }
        }

        private void addtolist2(string text)
        {
            if (this.listBox1.InvokeRequired)
            {
                SetText2Callback d = new SetText2Callback(addtolist2);
                this.Invoke(d, new object[] { text });
            }
            else
            {
                this.listBox2.Items.Add(text);
            }
        }
        
        public MySqlDataReader sqlexec(string info)
        {
            if (sql)
            {
                string mysqlString = "SERVER=" + textBox3.Text + ";" + "DATABASE=" + textBox5.Text + ";" + "UID=" + textBox2.Text + ";" + "PASSWORD=" + textBox4.Text + ";";

                conn = new MySqlConnection(mysqlString);
                conn.Open();

                MySqlCommand command = conn.CreateCommand();
                command.CommandText = info;
                Reader = command.ExecuteReader();

                conn.Close();

                return Reader;
            }

            return null;
        }

        public void getItems()
        {
            Clearlist();
            TorLib.Assets.assetPath = textBox1.Text;

            GomLib.DataObjectModel.Load();
            var itmList = GomLib.DataObjectModel.GetObjectsStartingWith("itm.").Where(obj => !obj.Name.StartsWith("itm.test.") && !obj.Name.StartsWith("itm.npc."));
            double i = 0;
            double ttl = itmList.Count();

            foreach (var gomItm in itmList)
            {
                GomLib.Models.Item itm = new GomLib.Models.Item();
                GomLib.ModelLoader.ItemLoader.Load(itm, gomItm);

                addtolist2("ItemName: " + itm.Name);

                System.IO.StreamWriter file2 = new System.IO.StreamWriter("c:\\swtor\\items.txt", true);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("ItemName: " + itm.Name + "\nItemNodeID: " + itm.NodeId + "\nNameId: " + itm.NameId);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("Item INFO");
                file2.WriteLine("    +ItemLevel: " + itm.ItemLevel);
                file2.WriteLine("    +ItemRequiredLevel: " + itm.RequiredLevel);
                file2.WriteLine("    +AppearanceColor: " + itm.AppearanceColor);
                file2.WriteLine("    +Description: " + itm.Description);
                file2.WriteLine("    +Icon: " + itm.Icon);
                file2.WriteLine("    +ArmorSpec: " + itm.ArmorSpec);
                file2.WriteLine("    +MaxStack: " + itm.MaxStack);
                file2.WriteLine("    +ModifierSpec: " + itm.ModifierSpec);
                file2.WriteLine("    +Quality: " + itm.Quality);
                file2.WriteLine("    +Rating: " + itm.Rating);
                file2.WriteLine("    +RequiredAlignmentInverte: " + itm.RequiredAlignmentInverted);
                file2.WriteLine("    +RequiredAlignmentTier: " + itm.RequiredAlignmentTier);
                file2.WriteLine("    +RequiredClasses: " + itm.RequiredClasses);
                file2.WriteLine("    +RequiredGender: " + itm.RequiredGender);
                file2.WriteLine("    +RequiredProfession: " + itm.RequiredProfession);
                file2.WriteLine("    +RequiredProfessionLevel: " + itm.RequiredProfessionLevel);
                file2.WriteLine("    +RequiredSocialTier: " + itm.RequiredSocialTier);
                file2.WriteLine("    +RequiredValorRank: " + itm.RequiredValorRank);
                file2.WriteLine("    +RequiresAlignment: " + itm.RequiresAlignment);
                file2.WriteLine("    +RequiresSocial: " + itm.RequiresSocial);
                file2.WriteLine("    +Schematic: " + itm.Schematic);
                file2.WriteLine("    +SchematicId: " + itm.SchematicId);
                file2.WriteLine("    +ShieldSpec: " + itm.ShieldSpec);
                file2.WriteLine("    +Slots: " + itm.Slots);
                file2.WriteLine("    +StatModifiers: " + itm.StatModifiers);
                file2.WriteLine("    +SubCategory: " + itm.SubCategory);
                file2.WriteLine("    +TreasurePackageId: " + itm.TreasurePackageId);
                file2.WriteLine("    +TreasurePackageSpec: " + itm.TreasurePackageSpec);
                file2.WriteLine("    +TypeBitSet: " + itm.TypeBitSet);
                file2.WriteLine("    +UniqueLimit: " + itm.UniqueLimit);
                file2.WriteLine("    +UseAbility: " + itm.UseAbility);
                file2.WriteLine("    +UseAbilityId: " + itm.UseAbilityId);
                file2.WriteLine("    +Value: " + itm.Value);
                file2.WriteLine("    +VendorStackSize: " + itm.VendorStackSize);
                file2.WriteLine("    +WeaponSpec: " + itm.WeaponSpec);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("\n\n");
                file2.Close();

              

                i++;
            }

            addtolist("the item lists has been generated there are " + i + " items");
            MessageBox.Show("the item lists has been generated there are " + i + " items");
        }

        public void getQuest()
        {
            Clearlist();
            TorLib.Assets.assetPath = textBox1.Text;
            double i = 0;

            GomLib.DataObjectModel.Load();
            var itmList = GomLib.DataObjectModel.GetObjectsStartingWith("qst.").Where(obj => !obj.Name.StartsWith("qst.test."));
            double ttl = itmList.Count();

            foreach (var gomItm in itmList)
            {
                GomLib.Models.Quest itm = new GomLib.Models.Quest();
                GomLib.ModelLoader.QuestLoader.Load(itm, gomItm);

                addtolist2("Quest Name: " + itm.Name);

                System.IO.StreamWriter file2 = new System.IO.StreamWriter("c:\\swtor\\Quest.txt", true);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("Quest Name: " + itm.Name + "\nQuest NodeId: " + itm.NodeId + "\nQuest Id: " + itm.Id);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("Quest INFO");
                file2.WriteLine("    +IsBonus: " + itm.IsBonus);
                file2.WriteLine("    +BonusShareable: " + itm.BonusShareable);
                file2.WriteLine("    +Branches: " + itm.Branches);
                file2.WriteLine("    +CanAbandon: " + itm.CanAbandon);
                file2.WriteLine("    +Category: " + itm.Category);
                file2.WriteLine("    +CategoryId: " + itm.CategoryId);
                file2.WriteLine("    +Classes: " + itm.Classes);
                file2.WriteLine("    +Difficulty: " + itm.Difficulty);
                file2.WriteLine("    +Fqn: " + itm.Fqn);
                file2.WriteLine("    +Icon: " + itm.Icon);
                file2.WriteLine("    +IsClassQuest: " + itm.IsClassQuest);
                file2.WriteLine("    +IsHidden: " + itm.IsHidden);
                file2.WriteLine("    +IsRepeatable: " + itm.IsRepeatable);
                file2.WriteLine("    +Items: " + itm.Items);
                file2.WriteLine("    +RequiredLevel: " + itm.RequiredLevel);
                file2.WriteLine("    +XpLevel: " + itm.XpLevel);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("\n\n");
                file2.Close();

                string name = itm.Name.Replace("'", " ");

                sqlexec("INSERT INTO `quest` (`quest_idc`, `quest_name`, `quest_nodeid`, `quest_id`, `IsBonus`, `BonusShareable`, `Branches`, `CanAbandon`, `Category`, `CategoryId`, `Classes`, `Difficulty`, `Fqn`, `Icon`, `IsClassQuest`, `IsHidden`, `IsRepeatable`, `Items`, `RequiredLevel`, `XpLevel`) VALUES (NULL, '" + name + "', '" + itm.NodeId + "', '" + itm.Id + "', '" + itm.IsBonus + "', '" + itm.BonusShareable + "', '" + itm.Branches + "', '" + itm.CanAbandon + "', '" + itm.Category + "', '" + itm.CategoryId + "', '" + itm.Classes + "', '" + itm.Difficulty + "', '" + itm.Fqn + "', '" + itm.Icon + "', '" + itm.IsClassQuest + "', '" + itm.IsHidden + "', '" + itm.IsRepeatable + "', '" + itm.Items + "', '" + itm.RequiredLevel + "', '" + itm.XpLevel + "');");

                i++;
            }

            addtolist("the Quest lists has been generated there are " + i + " Quests");
            MessageBox.Show("the Quest lists has been generated there are " + i + " Quests");
        }

        public void getnpc()
        {
            Clearlist();
            TorLib.Assets.assetPath = textBox1.Text;
            double i = 0;

            GomLib.DataObjectModel.Load();
            var itmList = GomLib.DataObjectModel.GetObjectsStartingWith("npc.").Where(obj => !obj.Name.StartsWith("npc.test."));
            double ttl = itmList.Count();

            foreach (var gomItm in itmList)
            {
                GomLib.Models.Npc itm = new GomLib.Models.Npc();
                GomLib.ModelLoader.NpcLoader.Load(itm, gomItm);

                addtolist2("npc Name: " + itm.Name);

                System.IO.StreamWriter file2 = new System.IO.StreamWriter("c:\\swtor\\npc.txt", true);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("npc Name: " + itm.Name + "\nnpc NodeId: " + itm.NodeId + "\nnpc Id: " + itm.Id);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("npc INFO");
                file2.WriteLine("    +ClassSpec: " + itm.ClassSpec);
                file2.WriteLine("    +Codex: " + itm.Codex);
                file2.WriteLine("    +CompanionOverride: " + itm.CompanionOverride);
                file2.WriteLine("    +Conversation: " + itm.Conversation);
                file2.WriteLine("    +ConversationFqn: " + itm.ConversationFqn);
                file2.WriteLine("    +DifficultyFlags: " + itm.DifficultyFlags);
                file2.WriteLine("    +Faction: " + itm.Faction);
                file2.WriteLine("    +Fqn: " + itm.Fqn);
                file2.WriteLine("    +IsClassTrainer: " + itm.IsClassTrainer);
                file2.WriteLine("    +IsVendor: " + itm.IsVendor);
                file2.WriteLine("    +LootTableId: " + itm.LootTableId);
                file2.WriteLine("    +MaxLevel: " + itm.MaxLevel);
                file2.WriteLine("    +MinLevel: " + itm.MinLevel);
                file2.WriteLine("    +ProfessionTrained: " + itm.ProfessionTrained);
                file2.WriteLine("    +Title: " + itm.Title);
                file2.WriteLine("    +Toughness: " + itm.Toughness);
                file2.WriteLine("    +VendorPackages: " + itm.VendorPackages);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("\n\n");
                file2.Close();

                i++;
            }

            addtolist("the npc lists has been generated there are " + i + " npc's");
            MessageBox.Show("the npc lists has been generated there are " + i + " npc's");
        }

        public void getCodex()
        {
            Clearlist();
            TorLib.Assets.assetPath = textBox1.Text;
            double i = 0;

            GomLib.DataObjectModel.Load();
            var itmList = GomLib.DataObjectModel.GetObjectsStartingWith("cdx.").Where(obj => !obj.Name.StartsWith("cdx.test."));
            double ttl = itmList.Count();

            foreach (var gomItm in itmList)
            {
                GomLib.Models.Codex itm = new GomLib.Models.Codex();
                GomLib.ModelLoader.CodexLoader.Load(itm, gomItm);

                addtolist2("Codex Title: " + itm.Title);

                System.IO.StreamWriter file2 = new System.IO.StreamWriter("c:\\swtor\\Codex.txt", true);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("Codex Title: " + itm.Title + "\nCodex NodeId: " + itm.NodeId + "\nCodex Id: " + itm.Id);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("Codex INFO");
                file2.WriteLine("    +CategoryId: " + itm.CategoryId);
                file2.WriteLine("    +Classes: " + itm.Classes);
                file2.WriteLine("    +ClassRestricted: " + itm.ClassRestricted);
                file2.WriteLine("    +Faction: " + itm.Faction);
                file2.WriteLine("    +Fqn: " + itm.Fqn);
                file2.WriteLine("    +HasPlanets: " + itm.HasPlanets);
                file2.WriteLine("    +Image: " + itm.Image);
                file2.WriteLine("    +IsHidden: " + itm.IsHidden);
                file2.WriteLine("    +IsPlanet: " + itm.IsPlanet);
                file2.WriteLine("    +Level: " + itm.Level);
                file2.WriteLine("    +Planets: " + itm.Planets);
                file2.WriteLine("    +Text: " + itm.Text);
                file2.WriteLine("------------------------------------------------------------");
                file2.WriteLine("\n\n");
                file2.Close();

                i++;
            }

            addtolist("the Codex lists has been generated there are " + i + " Codex's");
            MessageBox.Show("the Codex lists has been generated there are " + i + " Codex's");
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (sql)
            {
                listBox1.Items.Add("Mysql is now OFF");
                button3.Text = "Mysql OFF";
                sql = false;
            }else{
                listBox1.Items.Add("Mysql is now ON");
                button3.Text = "Mysql ON";
                sql = true;
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            dumper t = new dumper();
            t.Show();
        }

        private void textBox5_TextChanged(object sender, EventArgs e)
        {

        }
    }
}