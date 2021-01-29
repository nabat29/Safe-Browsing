using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Principal;
using System.DirectoryServices.AccountManagement;
using System.Drawing.Drawing2D;
using System.Xml;
using System.Data.SQLite;
using System.Diagnostics;

namespace SafeBrowser
{
    public static class SqliteReaderWriter
    {
        public static void ExecuteQuery(string insertorUpdq)
        {
            SQLiteConnection m_dbConnection = new SQLiteConnection("Data Source=db/sf.sqlite;Version=3;");
            //string sql2 = "insert into highscores (name, family, score) values ('Me', 'Asghari', 3000)";
            SQLiteCommand command2 = new SQLiteCommand(insertorUpdq, m_dbConnection);
            m_dbConnection.Open();
            command2.ExecuteNonQuery();
            m_dbConnection.Close();
        }
        public static DataTable ReadQuery(string selectq)
        {
            SQLiteConnection m_dbConnection = new SQLiteConnection("Data Source=db/sf.sqlite;Version=3;");
            m_dbConnection.Open();
            SQLiteCommand command = new SQLiteCommand(m_dbConnection);
            command.CommandText = selectq;//"SELECT score, name, family FROM highscores";

            DataSet DST = new DataSet();
            DataTable DT = new DataTable();
            SQLiteDataAdapter SDA = new SQLiteDataAdapter(command);

            SDA.Fill(DT);
            return DT;
        }
        public static object ExecuteScalar(string squery)
        {
            object rt;
            SQLiteConnection m_dbConnection = new SQLiteConnection("Data Source=db/sf.sqlite;Version=3;");
            //string sql2 = "insert into highscores (name, family, score) values ('Me', 'Asghari', 3000)";
            SQLiteCommand command2 = new SQLiteCommand(squery, m_dbConnection);
            m_dbConnection.Open();
            rt = command2.ExecuteScalar();
            m_dbConnection.Close();
            return rt;
        }
        public static int CountOfRow(string tableName, string Where)
        {
            int count = 0;
            count = Int32.Parse(ExecuteScalar("SELECT COUNT(*) FROM " + tableName + " " + Where).ToString());

            return count;
        }
        public static int CountOfRow(string tableName)
        {
            return CountOfRow(tableName, "");
        }
    }

    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {

            
        }

        private void Form1_Load(object sender, EventArgs e)
        {SecureDesktop.Run();
            try
            {
                
            }
            catch(Exception ex)
            {
                var st = new StackTrace(ex, true);
                // Get the top stack frame
                var frame = st.GetFrame(0);
                // Get the line number from the stack frame
                var line = frame.GetFileLineNumber();
                MessageBox.Show(line.ToString());
            }
            this.Close();
            //MessageBox.Show(System.Security.Principal.WindowsIdentity.GetCurrent().User.AccountDomainSid.ToString());
        }

       
    }
}
