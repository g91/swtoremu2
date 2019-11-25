using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace Swtor
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private string extractLang()
        {
            string[] file = Directory.GetFiles(Directory.GetCurrentDirectory() + "\\Assets\\", "assets_swtor_??_??_version.txt");
            Match matches = Regex.Match(file[0], @"(.*)[\\/]assets_swtor_([a-z]{2})_([a-z]{2})_version.txt");
            return matches.Groups[2].Value + "-" + matches.Groups[3].Value;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                string lang = extractLang();
                ProcessStartInfo info = new ProcessStartInfo(Directory.GetCurrentDirectory() + "\\swtor\\retailclient\\swtor-emu.exe", "-set username " + username.Text +
                    " -set password " + password.Text +
                    " -set platform emulatornexus.com:443 -set environment swtor " +
                    "-set lang " + lang + " -set torsets main," + lang + " @swtor_dual.icb");

                info.WorkingDirectory = Directory.GetCurrentDirectory() + "\\swtor\\retailclient";

                Process.Start(info);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Place EmuLauncher.exe in your swtor game folder !!!", "Critical Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}