using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using Ookii.Dialogs.Wpf;

namespace SCPTExtractor
{
    /// <summary>
    /// Interaction logic for ScriptDialog.xaml
    /// </summary>
    public partial class ScriptDialog : Window
    {
        private HeroScript Script;

        public ScriptDialog(HeroScript pScript)
        {
            InitializeComponent();
            this.HideIcon();
            Script = pScript;
            this.Title = pScript.Name + " Info";
            this.scriptName.Content = Script.Name;
            this.stringCount.Content = Script.Strings.Count;
            this.stringList.DataContext = Script.Strings;
        }

        private void button1_Click(object sender, RoutedEventArgs e)
        {
            Process.Start("explorer.exe", "/select,\"" + Script.Location + "\"");
        }

        private void CopyLogExecuted(object sender, ExecutedRoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(stringList.SelectedItem.ToString());
            }
            catch (Exception ex)
            {
                if (TaskDialog.OSSupportsTaskDialogs)
                {
                    using (TaskDialog dialog = new TaskDialog())
                    {
                        dialog.WindowTitle = "Application Error";
                        dialog.MainInstruction = "An error has occurred.";
                        dialog.Content = "An error occurred when trying to set clipboard data. This could be caused due to another application using the clipboard.\n\nYou can find detailed information below.";
                        dialog.ExpandedInformation = ex.ToString();
                        TaskDialogButton okButton = new TaskDialogButton(ButtonType.Ok);
                        dialog.Buttons.Add(okButton);
                        TaskDialogButton button = dialog.ShowDialog(this);
                    }
                }
                else
                {
                    MessageBox.Show(this, "An error occurred when trying to set clipboard data.\nThis could be caused due to another application using the clipboard.", "Application Error");
                }
            }
        }

        private void CanExecuteCopyLog(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            this.ExtendGlass();
            this.HideIcon();
        }
    }
}
