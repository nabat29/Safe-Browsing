using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SafeBrowser
{
    public partial class AddBookmark : Form
    {
        public AddBookmark()
        {
            InitializeComponent();
        }

        private void AddBookmark_Load(object sender, EventArgs e)
        { 
                       
            comboBox1.Items.Add(SafeBrowser.Properties.Resources.SSBookmark);
            comboBox1.Items.Add(SafeBrowser.Properties.Resources.SBBookmark);
            comboBox1.Items.Add(SafeBrowser.Properties.Resources.SEBookmark);
            comboBox1.Items.Add(SafeBrowser.Properties.Resources.SSHBookmark);
            
            comboBox1.Items.Add(SafeBrowser.Properties.Resources.SOBookmark);
            comboBox1.SelectedIndex = 4;
        }
        string s = "";
        private void button1_Click(object sender, EventArgs e)
        {
            
            if (textBox1.Text == "")
            {
                MessageBox.Show("Please enter URL!");
                return;
            }
            Uri uriResult;
            bool result = Uri.TryCreate((textBox1.Text.ToLower().StartsWith("http://")?"": "http://") +textBox1.Text, UriKind.Absolute, out uriResult)
                && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
            if(!result)
            {
                MessageBox.Show("Invalid URL!", "", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            int ID = SqliteReaderWriter.CountOfRow("tblMain") + 1;


            if (s == textBox1.Text)
            {
                MessageBox.Show("Already Added!", "", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            
            SqliteReaderWriter.ExecuteQuery("INSERT INTO tblMain (ID, URL, CATEGORY) VALUES ("+ID+", '"+textBox1.Text+"','"+comboBox1.SelectedIndex+"')");
            MessageBox.Show("Item Added Successfully!");
            s = textBox1.Text;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}
