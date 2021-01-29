using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Principal;
using System.DirectoryServices.AccountManagement;
using System.ComponentModel;
using System.Collections.Concurrent;
using System.Timers;
using System.Management;
using System.Reflection;

namespace SafeBrowser
{

   
    class ClipboardChangedEventArgs : EventArgs
    {
        public readonly IDataObject DataObject;

        public ClipboardChangedEventArgs(IDataObject dataObject)
        {
            DataObject = dataObject;
        }
    }
    
    class NCForm:Form
    {
        private const int WM_MOUSEACTIVATE = 0x0021;
        private const int MA_NOACTIVATEANDEAT = 0x0004;
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetCursorPos(out POINT lpPoint);
        protected override bool ShowWithoutActivation
        {
            get
            {
                return true;
            }
        }
        [StructLayout(LayoutKind.Sequential)]

        public struct POINT

        {

            public int x;

            public int y;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WINDOWPOS
        {
            public IntPtr hwnd;
            public IntPtr hwndInsertAfter;
            public int x;
            public int y;
            public int cx;
            public int cy;
            public uint flags;
        }


        protected override void WndProc(ref Message m)
        {
                const int WM_SYSCOMMAND = 0x0112;
            const int SC_MOVE = 0xF010;
            const int WM_LBUTTONDOWN = 0x0201;
            const int WM_WINDOWPOSCHANGING       =    0x0046;
            const int WM_LBUTTONUP                =    0x0202;
            const int WM_NCLBUTTONDBLCLK = 0x00A3; //double click on a title bar a.k.a. non-client area of the form

            switch (m.Msg)
            {
                case WM_SYSCOMMAND:             //preventing the form from being moved by the mouse.
                    int command = m.WParam.ToInt32() & 0xfff0;
                    if (command == SC_MOVE)
                        return;
                    break;
                    /*case WM_MOUSEACTIVATE:
                    m.Result = (IntPtr)MA_NOACTIVATEANDEAT;
                    return;*/
                case WM_WINDOWPOSCHANGING:
                    WINDOWPOS wps = (WINDOWPOS)(Marshal.PtrToStructure(m.LParam, typeof(WINDOWPOS)));
                    wps.hwndInsertAfter = (IntPtr)1;//bottom
                    Marshal.StructureToPtr(wps, m.LParam, true);
                    return;
                /*case WM_LBUTTONDOWN:
                    POINT p;
                    GetCursorPos(out p);
                    //InterceptMouse.proc(p.x|p.y<<16,IntPtr.Zero, IntPtr.Zero);
                    return;
                  */
            }

            if (m.Msg == WM_NCLBUTTONDBLCLK)       //preventing the form being resized by the mouse double click on the title bar.
            {
                m.Result = IntPtr.Zero;
                return;
            }

            base.WndProc(ref m);
        }
    }
      public static class ProcessExtension
    {
        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        
    }
    public static class ClipboardMonitor
    {



        //NOTE: The length of the byte array parameter must be always 256 bytes!
        public delegate void OnClipboardChangeEventHandler(ClipboardFormat format, object data);
        public static event OnClipboardChangeEventHandler OnClipboardChange;
        public static string text;
        public static void Start()
        {
            ClipboardWatcher.Start();
            ClipboardWatcher.OnClipboardChange += (ClipboardFormat format, object data) =>
            {
                if (OnClipboardChange != null)
                {
                    if (format == ClipboardFormat.Text || format == ClipboardFormat.Html || format == ClipboardFormat.UnicodeText)
                    {
                        text = data.ToString();
                    }
                    OnClipboardChange(format, data);
                }
            };
        }

        public static void Stop()
        {
            OnClipboardChange = null;
            ClipboardWatcher.Stop();
        }

        class ClipboardWatcher : Form
        {
            // static instance of this form
            private static ClipboardWatcher mInstance;

            // needed to dispose this form
            static IntPtr nextClipboardViewer;

            public delegate void OnClipboardChangeEventHandler(ClipboardFormat format, object data);
            public static event OnClipboardChangeEventHandler OnClipboardChange;

            // start listening
            public static void Start()
            {
                // we can only have one instance if this class
                if (mInstance != null)
                    return;

                Thread t = new Thread(new ParameterizedThreadStart(x =>
                {
                    Application.Run(new ClipboardWatcher());
                }));
                t.SetApartmentState(ApartmentState.STA); // give the [STAThread] attribute
                t.Start();
            }

            // stop listening (dispose form)
            public static void Stop()
            {
                mInstance.Invoke(new MethodInvoker(() =>
                {
                    ChangeClipboardChain(mInstance.Handle, nextClipboardViewer);
                }));
                mInstance.Invoke(new MethodInvoker(mInstance.Close));

                mInstance.Dispose();

                mInstance = null;
            }

            // on load: (hide this window)
            protected override void SetVisibleCore(bool value)
            {
                CreateHandle();

                mInstance = this;

                nextClipboardViewer = SetClipboardViewer(mInstance.Handle);

                base.SetVisibleCore(false);
            }

            [DllImport("User32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr SetClipboardViewer(IntPtr hWndNewViewer);

            [DllImport("User32.dll", CharSet = CharSet.Auto)]
            public static extern bool ChangeClipboardChain(IntPtr hWndRemove, IntPtr hWndNewNext);

            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern int SendMessage(IntPtr hwnd, int wMsg, IntPtr wParam, IntPtr lParam);

            // defined in winuser.h
            const int WM_DRAWCLIPBOARD = 0x308;
            const int WM_CHANGECBCHAIN = 0x030D;

            protected override void WndProc(ref Message m)
            {
                switch (m.Msg)
                {
                    case WM_DRAWCLIPBOARD:
                        ClipChanged();
                        SendMessage(nextClipboardViewer, m.Msg, m.WParam, m.LParam);
                        break;

                    case WM_CHANGECBCHAIN:
                        if (m.WParam == nextClipboardViewer)
                            nextClipboardViewer = m.LParam;
                        else
                            SendMessage(nextClipboardViewer, m.Msg, m.WParam, m.LParam);
                        break;

                    default:
                        base.WndProc(ref m);
                        break;
                }
            }

            static readonly string[] formats = Enum.GetNames(typeof(ClipboardFormat));

            private void ClipChanged()
            {
                IDataObject iData = Clipboard.GetDataObject();

                ClipboardFormat? format = null;

                foreach (var f in formats)
                {
                    if (iData.GetDataPresent(f))
                    {
                        format = (ClipboardFormat)Enum.Parse(typeof(ClipboardFormat), f);
                        break;
                    }
                }

                object data = iData.GetData(format.ToString());

                if (data == null || format == null)
                    return;

                if (OnClipboardChange != null)
                    OnClipboardChange((ClipboardFormat)format, data);
            }


        }
    }

    public enum ClipboardFormat : byte
    {
        /// <summary>Specifies the standard ANSI text format. This static field is read-only.
        /// </summary>
        /// <filterpriority>1</filterpriority>
        Text,
        /// <summary>Specifies the standard Windows Unicode text format. This static field
        /// is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        UnicodeText,
        /// <summary>Specifies the Windows device-independent bitmap (DIB) format. This static
        /// field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        Dib,
        /// <summary>Specifies a Windows bitmap format. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        Bitmap,
        /// <summary>Specifies the Windows enhanced metafile format. This static field is
        /// read-only.</summary>
        /// <filterpriority>1</filterpriority>
        EnhancedMetafile,
        /// <summary>Specifies the Windows metafile format, which Windows Forms does not
        /// directly use. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        MetafilePict,
        /// <summary>Specifies the Windows symbolic link format, which Windows Forms does
        /// not directly use. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        SymbolicLink,
        /// <summary>Specifies the Windows Data Interchange Format (DIF), which Windows Forms
        /// does not directly use. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        Dif,
        /// <summary>Specifies the Tagged Image File Format (TIFF), which Windows Forms does
        /// not directly use. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        Tiff,
        /// <summary>Specifies the standard Windows original equipment manufacturer (OEM)
        /// text format. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        OemText,
        /// <summary>Specifies the Windows palette format. This static field is read-only.
        /// </summary>
        /// <filterpriority>1</filterpriority>
        Palette,
        /// <summary>Specifies the Windows pen data format, which consists of pen strokes
        /// for handwriting software, Windows Forms does not use this format. This static
        /// field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        PenData,
        /// <summary>Specifies the Resource Interchange File Format (RIFF) audio format,
        /// which Windows Forms does not directly use. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        Riff,
        /// <summary>Specifies the wave audio format, which Windows Forms does not directly
        /// use. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        WaveAudio,
        /// <summary>Specifies the Windows file drop format, which Windows Forms does not
        /// directly use. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        FileDrop,
        /// <summary>Specifies the Windows culture format, which Windows Forms does not directly
        /// use. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        Locale,
        /// <summary>Specifies text consisting of HTML data. This static field is read-only.
        /// </summary>
        /// <filterpriority>1</filterpriority>
        Html,
        /// <summary>Specifies text consisting of Rich Text Format (RTF) data. This static
        /// field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        Rtf,
        /// <summary>Specifies a comma-separated value (CSV) format, which is a common interchange
        /// format used by spreadsheets. This format is not used directly by Windows Forms.
        /// This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        CommaSeparatedValue,
        /// <summary>Specifies the Windows Forms string class format, which Windows Forms
        /// uses to store string objects. This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        StringFormat,
        /// <summary>Specifies a format that encapsulates any type of Windows Forms object.
        /// This static field is read-only.</summary>
        /// <filterpriority>1</filterpriority>
        Serializable,
    }
    static class SecureDesktop
    {
        [DllImport("user32.dll")]
        public static extern IntPtr CreateDesktop(string lpszDesktop, IntPtr lpszDevice,
        IntPtr pDevmode, int dwFlags, uint dwDesiredAccess, IntPtr lpsa);

        [DllImport("user32.dll")]
        private static extern bool SwitchDesktop(IntPtr hDesktop);

        [DllImport("user32.dll")]
        public static extern bool CloseDesktop(IntPtr handle);

        [DllImport("user32.dll")]
        public static extern bool SetThreadDesktop(IntPtr hDesktop);

        [DllImport("user32.dll")]
        public static extern IntPtr GetThreadDesktop(int dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool SetProcessWindowStation(IntPtr hWinSta);

        [DllImport("kernel32.dll")]
        public static extern int GetCurrentThreadId();

        [DllImport("Kernel32.dll")]
        private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
       
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("User32.dll")]
        public static extern IntPtr GetDC(IntPtr hwnd);
        [DllImport("User32.dll")]
        public static extern void ReleaseDC(IntPtr hwnd, IntPtr dc);

         
    [DllImport("User32.dll", EntryPoint = "GetDesktopWindow")] 
    public static extern IntPtr GetDesktopWindow();

        [DllImport("User32.dll")]
        public static extern Int32 SetForegroundWindow(int hWnd);


        [DllImport("User32.dll")]
        public static extern Int32 GetForegroundWindow();


        [DllImport("User32.dll", EntryPoint = "UpdateWindow")] 

    public static extern int SendMessage(IntPtr hWnd, uint msg, int wparam, int lparam);



        [DllImport("user32.dll", SetLastError = true)]
        static extern int FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsIconic(int hWnd);


        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [Flags]
        public enum SetWindowPosFlags : uint
        {
            // ReSharper disable InconsistentNaming

            /// <summary>
            ///     If the calling thread and the thread that owns the window are attached to different input queues, the system posts the request to the thread that owns the window. This prevents the calling thread from blocking its execution while other threads process the request.
            /// </summary>
            SWP_ASYNCWINDOWPOS = 0x8000,

            /// <summary>
            ///     Prevents generation of the WM_SYNCPAINT message.
            /// </summary>
            SWP_DEFERERASE = 0x2000,

            /// <summary>
            ///     Draws a frame (defined in the window's class description) around the window.
            /// </summary>
            SWP_DRAWFRAME = 0x0020,

            /// <summary>
            ///     Applies new frame styles set using the SetWindowLong function. Sends a WM_NCCALCSIZE message to the window, even if the window's size is not being changed. If this flag is not specified, WM_NCCALCSIZE is sent only when the window's size is being changed.
            /// </summary>
            SWP_FRAMECHANGED = 0x0020,

            /// <summary>
            ///     Hides the window.
            /// </summary>
            SWP_HIDEWINDOW = 0x0080,

            /// <summary>
            ///     Does not activate the window. If this flag is not set, the window is activated and moved to the top of either the topmost or non-topmost group (depending on the setting of the hWndInsertAfter parameter).
            /// </summary>
            SWP_NOACTIVATE = 0x0010,

            /// <summary>
            ///     Discards the entire contents of the client area. If this flag is not specified, the valid contents of the client area are saved and copied back into the client area after the window is sized or repositioned.
            /// </summary>
            SWP_NOCOPYBITS = 0x0100,

            /// <summary>
            ///     Retains the current position (ignores X and Y parameters).
            /// </summary>
            SWP_NOMOVE = 0x0002,

            /// <summary>
            ///     Does not change the owner window's position in the Z order.
            /// </summary>
            SWP_NOOWNERZORDER = 0x0200,

            /// <summary>
            ///     Does not redraw changes. If this flag is set, no repainting of any kind occurs. This applies to the client area, the nonclient area (including the title bar and scroll bars), and any part of the parent window uncovered as a result of the window being moved. When this flag is set, the application must explicitly invalidate or redraw any parts of the window and parent window that need redrawing.
            /// </summary>
            SWP_NOREDRAW = 0x0008,

            /// <summary>
            ///     Same as the SWP_NOOWNERZORDER flag.
            /// </summary>
            SWP_NOREPOSITION = 0x0200,

            /// <summary>
            ///     Prevents the window from receiving the WM_WINDOWPOSCHANGING message.
            /// </summary>
            SWP_NOSENDCHANGING = 0x0800,

            /// <summary>
            ///     Retains the current size (ignores the cx and cy parameters).
            /// </summary>
            SWP_NOSIZE = 0x0001,

            /// <summary>
            ///     Retains the current Z order (ignores the hWndInsertAfter parameter).
            /// </summary>
            SWP_NOZORDER = 0x0004,

            /// <summary>
            ///     Displays the window.
            /// </summary>
            SWP_SHOWWINDOW = 0x0040,

            // ReSharper restore InconsistentNaming
        }


        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, SetWindowPosFlags uFlags);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsWindowVisible(IntPtr hWnd);




        [DllImport("user32.dll", EntryPoint = "ShowWindow", SetLastError = true)]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);

        enum DESKTOP_ACCESS : uint
        {
            DESKTOP_NONE = 0,
            DESKTOP_READOBJECTS = 0x0001,
            DESKTOP_CREATEWINDOW = 0x0002,
            DESKTOP_CREATEMENU = 0x0004,
            DESKTOP_HOOKCONTROL = 0x0008,
            DESKTOP_JOURNALRECORD = 0x0010,
            DESKTOP_JOURNALPLAYBACK = 0x0020,
            DESKTOP_ENUMERATE = 0x0040,
            DESKTOP_WRITEOBJECTS = 0x0080,
            DESKTOP_SWITCHDESKTOP = 0x0100,

            GENERIC_ALL = (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
                            DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
                            DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP),
        }
        static void ClipboardMonitor_OnClipboardChange(ClipboardFormat format, object data)
        {
            if (format != ClipboardFormat.Text)
                Clipboard.Clear();
            Console.WriteLine("Clipboard changed and it has the format: " + format.ToString());
        }
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public struct SECURITY_ATTRIBUTES
        {
            public int length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct CWPSTRUCT
        {
            public IntPtr lparam;
            public IntPtr wparam;
            public int message;
            public IntPtr hwnd;
        }

        [DllImport("USER32.dll")]
        static extern short GetKeyState(int nVirtKey);

        [DllImport("user32.dll", SetLastError = true)]
        static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        public delegate bool EnumWindowsProc(IntPtr hWnd, int lParam);


        [DllImport("user32.dll")]
private static extern int EnumDesktopWindows(IntPtr hDesktop, EnumWindowsProc ewp, int lParam);

        public static List<IntPtr> GetOpenWindows(IntPtr hdesktop)
        {
            List<IntPtr> windows = new List<IntPtr>();
            //List<uint> prc = new List<uint>();
            EnumDesktopWindows(hdesktop, (EnumWindowsProc)delegate (IntPtr hWnd, int lParam)
            {
                if (hWnd == IntPtr.Zero || !IsWindow(hWnd) || !IsWindowVisible(hWnd)) return true;
                //  uint pid;
                // prc.Add(GetWindowThreadProcessId(hWnd, out pid));
                
                windows.Add(hWnd);
                    
                
                return true;

            }, 0);
            //MessageBox.Show(Marshal.GetLastWin32Error()+"");
            return windows;
        }
        public static Process GetParent(this Process process)
        {
            try
            {
                using (var query = new ManagementObjectSearcher(
                  "SELECT * " +
                  "FROM Win32_Process " +
                  "WHERE ProcessId=" + process.Id))
                {
                    return query
                      .Get()
                      .OfType<ManagementObject>()
                      .Select(p => Process.GetProcessById((int)(uint)p["ParentProcessId"]))
                      .FirstOrDefault();
                }
            }
            catch
            {
                return null;
            }
        }
        public static List<Process> collection = new List<Process>();
        static List<IntPtr> wnds = new List<IntPtr>();
        public static object o;
        public static NCForm loginWnd;
        public static Panel panel;
        public static int BCNT = 0, wcount = 0, lastcount=0;
        private static PictureBox pbox2;
        static Color[] colors = new Color[50];
        static RectangleF[] recs = new RectangleF[50];
        static RectangleF[] Wrecs = new RectangleF[50];
        static long mycounter = 0;

        [DllImport("user32.dll")]
        static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags,
     bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Auto)]
        public static extern IntPtr GetParent(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetWindow(IntPtr hWnd, GetWindowType uCmd);

        private enum GetWindowType : uint
        {
            /// <summary>
            /// The retrieved handle identifies the window of the same type that is highest in the Z order.
            /// <para/>
            /// If the specified window is a topmost window, the handle identifies a topmost window.
            /// If the specified window is a top-level window, the handle identifies a top-level window.
            /// If the specified window is a child window, the handle identifies a sibling window.
            /// </summary>
            GW_HWNDFIRST = 0,
            /// <summary>
            /// The retrieved handle identifies the window of the same type that is lowest in the Z order.
            /// <para />
            /// If the specified window is a topmost window, the handle identifies a topmost window.
            /// If the specified window is a top-level window, the handle identifies a top-level window.
            /// If the specified window is a child window, the handle identifies a sibling window.
            /// </summary>
            GW_HWNDLAST = 1,
            /// <summary>
            /// The retrieved handle identifies the window below the specified window in the Z order.
            /// <para />
            /// If the specified window is a topmost window, the handle identifies a topmost window.
            /// If the specified window is a top-level window, the handle identifies a top-level window.
            /// If the specified window is a child window, the handle identifies a sibling window.
            /// </summary>
            GW_HWNDNEXT = 2,
            /// <summary>
            /// The retrieved handle identifies the window above the specified window in the Z order.
            /// <para />
            /// If the specified window is a topmost window, the handle identifies a topmost window.
            /// If the specified window is a top-level window, the handle identifies a top-level window.
            /// If the specified window is a child window, the handle identifies a sibling window.
            /// </summary>
            GW_HWNDPREV = 3,
            /// <summary>
            /// The retrieved handle identifies the specified window's owner window, if any.
            /// </summary>
            GW_OWNER = 4,
            /// <summary>
            /// The retrieved handle identifies the child window at the top of the Z order,
            /// if the specified window is a parent window; otherwise, the retrieved handle is NULL.
            /// The function examines only child windows of the specified window. It does not examine descendant windows.
            /// </summary>
            GW_CHILD = 5,
            /// <summary>
            /// The retrieved handle identifies the enabled popup window owned by the specified window (the
            /// search uses the first such window found using GW_HWNDNEXT); otherwise, if there are no enabled
            /// popup windows, the retrieved handle is that of the specified window.
            /// </summary>
            GW_ENABLEDPOPUP = 6
        }


        [Flags]
        public enum SPIF
        {
            None = 0x00,
            /// <summary>Writes the new system-wide parameter setting to the user profile.</summary>
            SPIF_UPDATEINIFILE = 0x01,
            /// <summary>Broadcasts the WM_SETTINGCHANGE message after updating the user profile.</summary>
            SPIF_SENDCHANGE = 0x02,
            /// <summary>Same as SPIF_SENDCHANGE.</summary>
            SPIF_SENDWININICHANGE = 0x02
        }

        #region SPI
        /// <summary>
        /// SPI_ System-wide parameter - Used in SystemParametersInfo function
        /// </summary>
        [Description("SPI_(System-wide parameter - Used in SystemParametersInfo function )")]
        public enum SPI : uint
        {
            /// <summary>
            /// Retrieves the size of the work area on the primary display monitor. The work area is the portion of the screen not obscured
            /// by the system taskbar or by application desktop toolbars. The pvParam parameter must point to a RECT structure that receives
            /// the coordinates of the work area, expressed in virtual screen coordinates.
            /// To get the work area of a monitor other than the primary display monitor, call the GetMonitorInfo function.
            /// </summary>
            SPI_GETWORKAREA = 0x0030
        }
        #endregion


        public const uint SPI_GETWORKAREA = 0x0030;
        public const uint SPIF_SENDCHANGE = 0x02;




// 1. Change the function to call the Unicode variant, where applicable.
// 2. Ask the marshaller to alert you to any errors that occur.
// 3. Change the parameter types to make marshaling easier. 
[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SystemParametersInfo(
                                                int uiAction,
                                                int uiParam,
                                                ref RECT pvParam,
                                                int fWinIni);

        private const Int32 SPIF_SENDWININICHANGE = 2;
        private const Int32 SPIF_UPDATEINIFILE = 1;
        private const Int32 SPIF_change = SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE;
        private const Int32 SPI_SETWORKAREA = 47;


        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public Int32 Left;
            public Int32 Top;   // top is before right in the native struct
            public Int32 Right;
            public Int32 Bottom;
        }

        private static bool SetWorkspace(RECT rect)
        {
            // Since you've declared the P/Invoke function correctly, you don't need to
            // do the marshaling yourself manually. The .NET FW will take care of it.
            bool result = SystemParametersInfo(SPI_SETWORKAREA,
                                               0,
                                               ref rect,
                                               SPIF_UPDATEINIFILE);
            if (!result)
            {
                // Find out the error code
                MessageBox.Show("The last error was: " +
                                Marshal.GetLastWin32Error().ToString());
            }

            return result;
        } 
        private static RECT GetWorkspace()
        {
            // Since you've declared the P/Invoke function correctly, you don't need to
            // do the marshaling yourself manually. The .NET FW will take care of it.
            RECT rect = new RECT();
            bool result = SystemParametersInfo(48,
                                               0,
                                               ref rect,
                                               SPIF_UPDATEINIFILE);
            if (!result)
            {
                // Find out the error code
                MessageBox.Show("The last error was: " +
                                Marshal.GetLastWin32Error().ToString());
            }

            return rect;
        }
        [DllImport("user32.dll", SetLastError = true)]
        static extern int MoveWindow(int hWnd, int x, int y, int w, int h, bool repaint);
       


        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        //                                 SPI_GETWORKAREA 0x0030, 0  ,pvParam points to Rec, send global change
        static extern bool SystemParametersInfo(SPI uiAction, uint uiParam, ref RECT pvParam, SPIF fWinIni);



      


        public static IEnumerable<Process> GetChildProcesses(this Process process)
        {
            List<Process> children = new List<Process>();
            ManagementObjectSearcher mos = new ManagementObjectSearcher(String.Format("Select * From Win32_Process Where ParentProcessID={0}", process.Id));
            foreach (ManagementObject mo in mos.Get())
            {
                children.Add(Process.GetProcessById(Convert.ToInt32(mo["ProcessID"])));
            }

            return children;
        }

        static async void runCmdCommad(string cmd)
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            //startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = $"/C {cmd}";
            process.StartInfo = startInfo;
            process.Start();
            await Task.Run(() => process.WaitForExit());
        }
        static async void DisableInternet(bool enable)
        {
            string disableNet = "wmic path win32_networkadapter where PhysicalAdapter=True call disable";
            string enableNet = "wmic path win32_networkadapter where PhysicalAdapter=True call enable";
            await Task.Run(() => runCmdCommad(enable ? enableNet : disableNet));
        }

        static void ExecuteCommand(string command)
        {
            int ExitCode;
            ProcessStartInfo ProcessInfo;
            Process process;

            ProcessInfo = new ProcessStartInfo(command);
            ProcessInfo.CreateNoWindow = true;
            ProcessInfo.UseShellExecute = false;

            // *** Redirect the output ***
            ProcessInfo.RedirectStandardError = true;
            ProcessInfo.RedirectStandardOutput = true;

            process = Process.Start(ProcessInfo);
            process.WaitForExit();

     
            process.Close();
        }

        private static string tempdir = System.IO.Path.GetTempPath();
        static int n2 = -1, npp = -1;
        public static void Run()
        {
            try
            {
                o = new object();
                // old desktop's handle, obtained by getting the current desktop assigned for this thread
                IntPtr hOldDesktop = GetThreadDesktop(GetCurrentThreadId());
                IntPtr oldpr = Process.GetCurrentProcess().Handle;
                // new desktop's handle, assigned automatically by CreateDesktop
                IntPtr hNewDesktop = CreateDesktop("WebroamDesktop",
                 IntPtr.Zero, IntPtr.Zero, 0, (uint)(DESKTOP_ACCESS.DESKTOP_SWITCHDESKTOP | DESKTOP_ACCESS.DESKTOP_CREATEWINDOW), IntPtr.Zero);
                int psbits = 0;
                // iq = new List<int>();
                string sid = Registry.Users.GetSubKeyNames().First(s => s.StartsWith(System.Security.Principal.WindowsIdentity.GetCurrent().User.AccountDomainSid.ToString() + "-1"));
                //MessageBox.Show("1");
                RegistryKey key = Registry.Users.OpenSubKey(sid + @"\SOFTWARE\Clients\StartMenuInternet");
                //MessageBox.Show("2");
                string[] browsers = new string[0];
                // MessageBox.Show(System.Security.Principal.WindowsIdentity.GetCurrent().User.AccountDomainSid.ToString() +"-1001"+ @"\Software\Clients\StartMenuInternet");
                for (int i = 0; i < Wrecs.Count();i++)
                {
                    Wrecs[i].X = 0;
                }
               
                    if (key!=null && key.SubKeyCount > 0)
                {

                    browsers = key.GetSubKeyNames();
                   // MessageBox.Show("3");
                }
                else
                {
                    key = Registry.LocalMachine.OpenSubKey(@"Software\Clients\StartMenuInternet", false);
                  if(key!= null && key.SubKeyCount>0)
                    browsers = key.GetSubKeyNames();
                }

                string f0 = "", f1 = "", f2 = "";
                if (key != null && browsers.Length > 0)
                {
                    if (browsers.FirstOrDefault(s => s.ToLower().Contains("firefox")) != null)
                        if (key.OpenSubKey(browsers.FirstOrDefault(s => s.ToLower().Contains("firefox"))) != null)
                            f0 = key.OpenSubKey(browsers.FirstOrDefault(s => s.ToLower().Contains("firefox"))).OpenSubKey("shell\\open\\command").GetValue(null).ToString().Replace("\"", "");

                    if (browsers.FirstOrDefault(s => s.ToLower().Contains("chrome")) != null)
                        if (key.OpenSubKey(browsers.FirstOrDefault(s => s.ToLower().Contains("chrome"))) != null)
                            f1 = key.OpenSubKey(browsers.FirstOrDefault(s => s.ToLower().Contains("chrome"))).OpenSubKey("shell\\open\\command").GetValue(null).ToString().Replace("\"", "");
                }
                // if (key.OpenSubKey(browsers.First(s => s.ToLower().Contains("opera"))) != null)
                //      f11 = key.OpenSubKey(browsers.First(s => s.ToLower().Contains("opera"))).OpenSubKey("shell\\open\\command").GetValue(null).ToString().Replace("\"", "");
                if (f1 == "")
                {
                    var path = Microsoft.Win32.Registry.GetValue(@"HKEY_CLASSES_ROOT\ChromeHTML\shell\open\command", null, null) as string;
                    if (path != null)
                    {
                        var split = path.Split('\"');
                        path = split.Length >= 2 ? split[1] : null;
                    }
                    f1 = path;
                }
                // MessageBox.Show(f11);
                f2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Clients\StartMenuInternet\IEXPLORE.EXE").OpenSubKey("shell\\open\\command").GetValue(null).ToString().Replace("\"", "");
                
                if (f0 != "")
                {
                    BCNT++;
                    psbits |= 1;
                }
                if (f1 != "")
                {
                    BCNT++;
                    psbits |= 1 << 1;
                }
                if (f2 != "")
                {
                    BCNT++;
                    psbits |= 1 << 2;
                }
                //System.Diagnostics.Process.Start(f1);
                SwitchDesktop(hNewDesktop);
                // Random login form: used for testing / not required

                ClipboardMonitor.Start();

                ClipboardMonitor.OnClipboardChange += new ClipboardMonitor.OnClipboardChangeEventHandler(ClipboardMonitor_OnClipboardChange);
                colors = Array.ConvertAll<Color, Color>(colors, color => color = Color.White);
                // 

                //     ClipboardMonitor.Stop(); // do not forget to stop
                /*   var chrms = System.Diagnostics.Process.GetProcessesByName("chrome");
                    foreach (var c in chrms)
                        c.Suspend();
                  */
           
                float widthRatio = Screen.PrimaryScreen.Bounds.Width / 1600f;
                float heightRatio = Screen.PrimaryScreen.Bounds.Height / 900f;
                RECT Rect = new RECT();
                Rect.Left = 0;
                Rect.Top = 70;
                Rect.Right = 1400;
                Rect.Bottom = 850;
                RECT oldRect = GetWorkspace();
                
                int tempHeight = 0, tempWidth = 0;
                Screen Srn = Screen.PrimaryScreen;
                tempHeight = Srn.Bounds.Width;
                tempWidth = Srn.Bounds.Height;

                // running on a different thread, this way SetThreadDesktop won't fail
                var tr = new Thread(delegate ()
                        {
                    // assigning the new desktop to this thread - 
                    // so the Form will be shown in the new desktop)
                    //Thread.CurrentThread.TrySetApartmentState(ApartmentState.STA);

                    SetThreadDesktop(hNewDesktop);
                    SetProcessWindowStation((IntPtr)GetCurrentThreadId());
                    //System.Diagnostics.Process.Start(f2);

                    int FixHeight = 900, FixWidth = 1600;

                    Resolution.CResolution ChangeRes = new Resolution.CResolution(1600, 900);

                    loginWnd = new NCForm();

                    PROCESS_INFORMATION pi1 = new PROCESS_INFORMATION();
                    STARTUPINFO si1 = new STARTUPINFO();
                    si1.lpDesktop = "WebroamDesktop";
                    Panel topPanel = new Panel();
                    topPanel.Location = new Point(0, 0);
                    topPanel.Size = new Size(1600, 70);
                    topPanel.BackColor = Color.FromArgb(200, 0, 0, 0);

                    loginWnd.Controls.Add(topPanel);

                    panel = new Panel();
                    // panel.FormBorderStyle = FormBorderStyle.None;
                    panel.Location = new Point(0, 840);
                    panel.Size = new Size(1600, 60);
                    panel.BackColor = Color.Black;
                    //panel.StartPosition = FormStartPosition.Manual;
                    //loginWnd.Controls.Add(panel);
                    loginWnd.Controls.Add(panel);
                    PictureBox pbox0 = new PictureBox();
                    pbox0.SizeMode = PictureBoxSizeMode.CenterImage;
                    if (f0 != "")
                        pbox0.Image = Bitmap.FromHicon(Icon.ExtractAssociatedIcon(f0).Handle);
                    else
                        pbox0.Visible = false;
                    pbox0.Location = new Point(10, 12);
                    pbox0.Size = new Size(40, 38);
                    pbox0.Paint += delegate (object sender2, PaintEventArgs e2) { if (pbox0.BorderStyle == BorderStyle.FixedSingle) ControlPaint.DrawBorder(e2.Graphics, pbox0.ClientRectangle, Color.LightGreen, ButtonBorderStyle.Solid); };
                    pbox0.MouseLeave += (sender2, e2) => pbox0.BorderStyle = BorderStyle.None;
                    pbox0.MouseEnter += delegate (object sender2, EventArgs e2)
                    {
                        pbox0.BorderStyle = BorderStyle.FixedSingle;
                    };
                    pbox0.MouseMove += (sender2, e2) => pbox0.BorderStyle = BorderStyle.FixedSingle;
                    pbox0.BackColor = Color.Black;

                    panel.Controls.Add(pbox0);
                    panel.MouseMove += Panel_MouseMove;
                    PictureBox pbox1 = new PictureBox();
                    pbox1.SizeMode = PictureBoxSizeMode.StretchImage;
                    pbox1.Image = f1 == "" ? Bitmap.FromHicon(Icon.ExtractAssociatedIcon(f2).Handle) : SafeBrowser.Properties.Resources.chrome;//Image.FromFile("images/chrome.png");//Bitmap.FromHicon(Icon.ExtractAssociatedIcon(f1).Handle);
                    pbox1.Location = new Point(((psbits & 1) * 70), 12);
                    pbox1.BackColor = Color.Black;
                    pbox1.Size = new Size(40, 38);
                    pbox1.MouseLeave += (sender2, e2) => pbox1.BorderStyle = BorderStyle.None;
                    pbox1.MouseEnter += (sender2, e2) => pbox1.BorderStyle = BorderStyle.FixedSingle;
                    pbox1.MouseMove += (sender2, e2) => pbox1.BorderStyle = BorderStyle.FixedSingle;
                    pbox1.Paint += delegate (object sender2, PaintEventArgs e2) { if (pbox1.BorderStyle == BorderStyle.FixedSingle) ControlPaint.DrawBorder(e2.Graphics, pbox1.ClientRectangle, Color.LightGreen, ButtonBorderStyle.Solid); };

                    panel.Controls.Add(pbox1);



                    pbox2 = new PictureBox();
                    pbox2.SizeMode = PictureBoxSizeMode.CenterImage;
                    pbox2.Image = Bitmap.FromHicon(Icon.ExtractAssociatedIcon(f2).Handle);
                    pbox2.Location = new Point(((psbits & 1) * 70) + (((psbits >> 1) & 1) * 70), 12);
                    pbox2.Size = new Size(40, 38);
                    pbox2.MouseLeave += (sender2, e2) => pbox2.BorderStyle = BorderStyle.None;
                    pbox2.MouseEnter += delegate (object sender2, EventArgs e2)
                    {
                        pbox2.BorderStyle = BorderStyle.FixedSingle;
                    };
                    pbox2.MouseMove += delegate (object sender3, MouseEventArgs e3)
                    {
                        pbox2.BorderStyle = BorderStyle.FixedSingle;

                    };
                    pbox2.Paint += delegate (object sender, PaintEventArgs e) { if (pbox2.BorderStyle == BorderStyle.FixedSingle) ControlPaint.DrawBorder(e.Graphics, pbox2.ClientRectangle, Color.LightGreen, ButtonBorderStyle.Solid); };

                    panel.Controls.Add(pbox2);


                    panel.MouseMove += delegate (object sender, MouseEventArgs e)
                    {
                        pbox0.BorderStyle = BorderStyle.None;
                        pbox1.BorderStyle = BorderStyle.None;
                            //pbox.BorderStyle = BorderStyle.None;
                            pbox2.BorderStyle = BorderStyle.None;


                    };
                    Label lbl = new Label();
                    lbl.ForeColor = Color.White;
                    lbl.BackColor = Color.Black;
                    lbl.Text = DateTime.Now.ToShortTimeString();
                    lbl.AutoSize = true;
                    lbl.Location = new Point(1500, 22);
                    panel.Controls.Add(lbl);

                    Label lbl2 = new Label();
                    lbl2.ForeColor = Color.White;
                    lbl2.BackColor = Color.Black;
                    lbl2.Text = DateTime.Now.ToShortDateString();
                    lbl2.AutoSize = true;
                    lbl2.Location = new Point(1500, 38);
                    panel.Controls.Add(lbl2);
                    panel.AutoScroll = true;
                    // panel.Controls.Add(pbox);
                    loginWnd.FormBorderStyle = FormBorderStyle.None;
                    loginWnd.Location = new Point(-100, 0);
                    loginWnd.Size = new Size(800, 1000);
                    loginWnd.BackColor = Color.DarkGray;
                    loginWnd.MinimizeBox = false;
                    loginWnd.MaximizeBox = false;
                    loginWnd.WindowState = FormWindowState.Maximized;
                    loginWnd.TopMost = false;
                    loginWnd.Opacity = 0.8;
                    Button btn = new Button();
                    btn.BackgroundImage = SafeBrowser.Properties.Resources.exit;

                    btn.BackgroundImageLayout = ImageLayout.Stretch;

                    btn.Size = new Size(60, 55);
                    btn.BackColor = Color.Red;
                    btn.Location = new Point(10, 10);





                    btn.Click += delegate (object sender, EventArgs e)
                {

                        // SetWindowPos(loginWnd.Handle, new IntPtr(1), 0, 0, 0, 0, SetWindowPosFlags.SWP_NOMOVE | SetWindowPosFlags.SWP_NOSIZE);
                        loginWnd.Close();
                        //

                        //MessageBox.Show(cmu.MenuItems.Count.ToString());
                        //cmu.Show(loginWnd, btn.Location);
                    };

                    topPanel.Controls.Add(btn);

                    Button btn01 = new Button();
                    btn01.BackgroundImage = SafeBrowser.Properties.Resources.kbord;

                    btn01.BackgroundImageLayout = ImageLayout.Stretch;

                    btn01.Size = new Size(60, 55);
                    btn01.BackColor = Color.White;
                    btn01.Location = new Point(70, 10);



                    //Task.Factory.StartNew(()=>);

                    btn01.Click += delegate (object sender, EventArgs e)
                    {
                        PROCESS_INFORMATION pi0 = new PROCESS_INFORMATION();
                        STARTUPINFO si0 = new STARTUPINFO();
                        si0.wShowWindow = 4;
                        si0.lpDesktop = "WebroamDesktop";
                        CreateProcess(Environment.CurrentDirectory + "\\kbd\\kb.exe", "", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si0, out pi0);
                    };

                    topPanel.Controls.Add(btn01);
                    Panel bookmark1 = new Panel();
                    bookmark1.Left = btn.Left + bookmark1.Width;
                    bookmark1.Top = btn.Bottom;
                    bookmark1.Dock = DockStyle.Right;
                    bookmark1.BackColor = Color.FromArgb(0, 99, 177);
                    bookmark1.BorderStyle = BorderStyle.Fixed3D;

                    Panel bookmark = new Panel();
                    bookmark.Left = 1800;
                    bookmark.Top = topPanel.Bottom;
                    bookmark.Height = 830;
                    bookmark.BackColor = Color.FromArgb(0, 99, 177);
                    bookmark.BorderStyle = BorderStyle.Fixed3D;
                    Panel bp1 = new Panel();
                    Panel bp2 = new Panel();
                    Panel bp3 = new Panel();
                    Panel bp4 = new Panel();
                    Panel bp5 = new Panel();
                    Panel bp6 = new Panel();
                    Panel bp7 = new Panel();

                    Button bbp1 = new Button();
                    bbp1.FlatStyle = FlatStyle.Flat;
                    bbp1.Text = SafeBrowser.Properties.Resources.SVbookmark;
                    bbp1.BackColor = Color.FromArgb(242, 103, 37);
                    bbp1.ForeColor = Color.White;
                    bbp1.Font = new Font("Ariel", 14);
                    bbp1.AutoSize = true;
                    bbp1.Dock = DockStyle.Top;
                    bp1.Dock = DockStyle.Top;
                    bp1.Height = bbp1.Height + 10;
                    bp1.Controls.Add(bbp1);
                    bp1.Name = "ViewB";
                    var tmm = new System.Windows.Forms.Timer();
                    tmm.Interval = 50000;

                    tmm.Tick += delegate (object ss, EventArgs aa)
                    {
                        tmm.Stop();
                        for (int ct = 0; ct < bookmark.Controls.Count; ct++)
                        {
                            if (bookmark.Controls[ct].Name == "")
                                bookmark.Controls[ct].Visible = false;
                        }
                        bbp1.Enabled = true;
                    };

                    Button bbp2 = new Button();
                    bbp2.FlatStyle = FlatStyle.Flat;
                    bbp2.Text = SafeBrowser.Properties.Resources.SAbookmark;
                    bbp2.BackColor = Color.FromArgb(40, 199, 77);
                    bbp2.ForeColor = Color.White;
                    bbp2.Font = new Font("Ariel", 14);
                    bbp2.AutoSize = true;
                    bbp2.Dock = DockStyle.Top;
                    bp2.Dock = DockStyle.Top;
                    bp2.Height = bbp2.Height + 10;
                    bp2.Controls.Add(bbp2);
                    bp2.Name = "AddB";
                    bbp2.Click += delegate (object ob1, EventArgs ev1)
                    {
                        new AddBookmark().Show();
                    };
                    Button bbp3 = new Button();
                    bbp3.FlatStyle = FlatStyle.Flat;
                    bbp3.Text = SafeBrowser.Properties.Resources.SSBookmark;
                    bbp3.BackColor = Color.FromArgb(48, 168, 228);
                    bbp3.ForeColor = Color.White;
                    bbp3.Font = new Font("Ariel", 14);
                    bbp3.AutoSize = true;
                    bbp3.Dock = DockStyle.Top;
                    bp3.Dock = DockStyle.Top;
                    bp3.Height = bbp3.Height + 10;
                    bp3.Controls.Add(bbp3);
                    Panel scbp3 = new Panel();
                    scbp3.Name = "scbp";
                    scbp3.Location = new Point(bbp3.Location.X, bbp3.Height);
                    scbp3.Size = new Size(bbp3.Width, 140 - bbp3.Height);
                    scbp3.HorizontalScroll.Maximum = 0;
                    scbp3.HorizontalScroll.Visible = false;
                    scbp3.AutoScroll = true;
                    bp3.Controls.Add(scbp3);
                    bbp3.Click += delegate (object ob1, EventArgs ev1)
    {

        for (int k = 0; k < bookmark.Controls.Count; k++)
        {
            if (bookmark.Controls[k].GetType() == panel.GetType())
            {
                bp1.GetType().GetProperty("Height").SetValue(bookmark.Controls[k], bbp1.Height);
                bp1.GetType().GetProperty("AutoScroll").SetValue(bookmark.Controls[k], false);
            }
        }
        bp3.Height = 140;
            //    bp3.AutoScroll = true;
            tmm.Stop();
        tmm.Start();
    };
                    Button bbp4 = new Button();
                    bbp4.FlatStyle = FlatStyle.Flat;
                    bbp4.Text = SafeBrowser.Properties.Resources.SBBookmark;
                    bbp4.BackColor = Color.FromArgb(48, 168, 228);
                    bbp4.ForeColor = Color.White;
                    bbp4.Font = new Font("Ariel", 14);
                    bbp4.AutoSize = true;
                    bbp4.Dock = DockStyle.Top;
                    bp4.Dock = DockStyle.Top;
                    bp4.Height = bbp4.Height + 10;
                    bp4.Controls.Add(bbp4);
                    Panel scbp4 = new Panel();
                    scbp4.Name = "scbp";
                    scbp4.Location = new Point(bbp4.Location.X, bbp4.Height);
                    scbp4.Size = new Size(bbp4.Width, 140 - bbp4.Height);
                    scbp4.HorizontalScroll.Maximum = 0;
                    scbp4.HorizontalScroll.Visible = false;
                    scbp4.AutoScroll = true;
                    bp4.Controls.Add(scbp4);
                    bbp4.Click += delegate (object ob1, EventArgs ev1)
                    {

                        for (int k = 0; k < bookmark.Controls.Count; k++)
                        {
                            if (bookmark.Controls[k].GetType() == panel.GetType())
                            {
                                bp1.GetType().GetProperty("Height").SetValue(bookmark.Controls[k], bbp1.Height);
                                bp1.GetType().GetProperty("AutoScroll").SetValue(bookmark.Controls[k], false);
                            }
                        }
                        bp4.Height = 140;
                            //bp4.AutoScroll = true;
                            tmm.Stop();
                        tmm.Start();
                    };

                    Button bbp5 = new Button();
                    bbp5.FlatStyle = FlatStyle.Flat;
                    bbp5.Text = SafeBrowser.Properties.Resources.SEBookmark;
                    bbp5.BackColor = Color.FromArgb(48, 168, 228);
                    bbp5.ForeColor = Color.White;
                    bbp5.Font = new Font("Ariel", 14);
                    bbp5.AutoSize = true;
                    bbp5.Dock = DockStyle.Top;
                    bp5.Dock = DockStyle.Top;
                    bp5.Height = bbp5.Height + 10;
                    bp5.Controls.Add(bbp5);
                    Panel scbp5 = new Panel();
                    scbp5.Name = "scbp";
                    scbp5.Location = new Point(bbp5.Location.X, bbp5.Height);
                    scbp5.Size = new Size(bbp5.Width, 140 - bbp5.Height);
                    scbp5.HorizontalScroll.Maximum = 0;
                    scbp5.HorizontalScroll.Visible = false;
                    scbp5.AutoScroll = true;
                    bp5.Controls.Add(scbp5);
                    bbp5.Click += delegate (object ob1, EventArgs ev1)
    {

        for (int k = 0; k < bookmark.Controls.Count; k++)
        {
            if (bookmark.Controls[k].GetType() == panel.GetType())
            {
                bp1.GetType().GetProperty("Height").SetValue(bookmark.Controls[k], bbp1.Height);
                bp1.GetType().GetProperty("AutoScroll").SetValue(bookmark.Controls[k], false);
            }
        }
        bp5.Height = 140;
            //  bp5.AutoScroll = true;
            tmm.Stop();
        tmm.Start();
    };


                    Button bbp6 = new Button();
                    bbp6.FlatStyle = FlatStyle.Flat;
                    bbp6.Text = SafeBrowser.Properties.Resources.SSHBookmark;
                    bbp6.BackColor = Color.FromArgb(48, 168, 228);
                    bbp6.ForeColor = Color.White;
                    bbp6.Font = new Font("Ariel", 14);
                    bbp6.AutoSize = true;
                    bbp6.Dock = DockStyle.Top;
                    bp6.Dock = DockStyle.Top;
                    bp6.Height = bbp6.Height + 10;
                    bp6.Controls.Add(bbp6);
                    Panel scbp6 = new Panel();
                    scbp6.Name = "scbp";
                    scbp6.Location = new Point(bbp6.Location.X, bbp6.Height);
                    scbp6.Size = new Size(bbp6.Width, 140 - bbp6.Height);
                    scbp6.HorizontalScroll.Maximum = 0;
                    scbp6.HorizontalScroll.Visible = false;
                    //   scbp6.AutoScroll = true;
                    bp6.Controls.Add(scbp6);
                    bbp6.Click += delegate (object ob1, EventArgs ev1)
    {

        for (int k = 0; k < bookmark.Controls.Count; k++)
        {
            if (bookmark.Controls[k].GetType() == panel.GetType())
                bp1.GetType().GetProperty("Height").SetValue(bookmark.Controls[k], bbp1.Height);
        }
        bp6.Height = 140;
            //  bp6.AutoScroll = true;
            tmm.Stop();
        tmm.Start();
    };

                    Button bbp7 = new Button();
                    bbp7.FlatStyle = FlatStyle.Flat;
                    bbp7.Text = SafeBrowser.Properties.Resources.SOBookmark;
                    bbp7.BackColor = Color.FromArgb(48, 168, 228);
                    bbp7.ForeColor = Color.White;
                    bbp7.Font = new Font("Ariel", 14);
                    bbp7.AutoSize = true;
                    bbp7.Dock = DockStyle.Top;
                    bp7.Dock = DockStyle.Top;
                    bp7.Height = bbp7.Height + 10;
                    bp7.Controls.Add(bbp7);
                    Panel scbp7 = new Panel();
                    scbp7.Name = "scbp";
                    scbp7.Location = new Point(bbp7.Location.X, bbp7.Height);
                    scbp7.Size = new Size(bbp7.Width, 140 - bbp7.Height);
                    scbp7.HorizontalScroll.Maximum = 0;
                    scbp7.HorizontalScroll.Visible = false;
                    scbp7.AutoScroll = true;
                    bp7.Controls.Add(scbp7);
                    bbp7.Click += delegate (object ob1, EventArgs ev1)
    {

        for (int k = 0; k < bookmark.Controls.Count; k++)
        {
            if (bookmark.Controls[k].GetType() == panel.GetType())
            {
                bp1.GetType().GetProperty("Height").SetValue(bookmark.Controls[k], bbp1.Height);
                bp1.GetType().GetProperty("AutoScroll").SetValue(bookmark.Controls[k], false);
            }
        }
        bp7.Height = 140;
            //bp7.AutoScroll = true;
            tmm.Stop();
        tmm.Start();
    };

                    bbp1.Click += delegate (object ob1, EventArgs ev1)
        {
            bbp1.Enabled = false;
            for (int ct = 0; ct < bookmark.Controls.Count; ct++)
            {
                bookmark.Controls[ct].Visible = true;
            }
            var dbt = SqliteReaderWriter.ReadQuery("SELECT * FROM tblMain");
            Dictionary<int, int> counter = new Dictionary<int, int>();
            Panel[] bbpss = new Panel[5];
            bbpss[0] = bp3;
            bbpss[1] = bp4;
            bbpss[2] = bp5;
            bbpss[3] = bp6;
            bbpss[4] = bp7;
            for (int k = 0; k < dbt.Rows.Count; k++)
            {
                int index = Int32.Parse(dbt.Rows[k]["Category"].ToString());
                if (!counter.Keys.Contains(index))
                    counter.Add(index, 0);

                LinkLabel ll = new LinkLabel();
                ll.Font = new Font("Ariel", 12);
                ll.LinkColor = Color.White;
                ll.BackColor = Color.SkyBlue;
                ll.Text = dbt.Rows[k]["URL"].ToString();
                ll.Location = new Point(bbpss[index].Location.X, bbpss[index].Height * counter[index]);
                ll.Size = bbpss[index].Size;
                counter[index]++;
                string dirNm2 = tempdir + "\\data22\\" + new Random().Next(1865);
                Directory.CreateDirectory(dirNm2);
                PROCESS_INFORMATION pi2 = new PROCESS_INFORMATION();
                STARTUPINFO si2 = new STARTUPINFO();
                si2.wShowWindow = 4;
                si2.lpDesktop = "WebroamDesktop";
                ll.Click += delegate (object oo, EventArgs ea) { CreateProcess(f1, " --user-data-dir=" + dirNm2 + " --new-window --incognito " + ll.Text, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si2, out pi2); };
                bbpss[index].Controls["scbp"].Controls.Add(ll);

            }
            tmm.Stop();
            tmm.Start();
        };

                    bookmark1.Controls.Add(bp1);
                    bookmark1.Controls.Add(bp2);
                    bookmark.Controls.Add(bp3);
                    bookmark.Controls.Add(bp4);
                    bookmark.Controls.Add(bp5);
                    bookmark.Controls.Add(bp6);
                    bookmark.Controls.Add(bp7);
                    Control[] arc = new Control[bookmark.Controls.Count];
                    bookmark.Controls.CopyTo(arc, 0);
                    bookmark.Controls.Clear();
                    bookmark.Controls.AddRange(arc.Reverse().ToArray());
                    for (int ct = 0; ct < bookmark.Controls.Count; ct++)
                    {
                        if (bookmark.Controls[ct].Name == "")
                            bookmark.Controls[ct].Visible = false;
                    }
                    topPanel.Controls.Add(bookmark1);
                    loginWnd.Controls.Add(bookmark);
                    loginWnd.MouseUp += delegate (object ss, MouseEventArgs ar)
    {
            //loginWnd.Opacity = 1;
            //StringBuilder sb = new StringBuilder();

        };
                    loginWnd.MouseDown += delegate (object ss, MouseEventArgs ar)
                    {
                            //SetWindowPos(loginWnd.Handle, new IntPtr(1), 0, 0, 0, 0, SetWindowPosFlags.SWP_NOMOVE | SetWindowPosFlags.SWP_NOSIZE);
                            //loginWnd.Opacity = 0.3;

                        };
                    //var tchk = new System.Windows.Forms.Timer();
                    var timr = new System.Windows.Forms.Timer();
                    timr.Interval = 10;

                    SetWorkspace(Rect);
                    Rectangle r = pbox0.Bounds;
                    Rectangle r2 = pbox1.Bounds;
                    Rectangle r3 = pbox2.Bounds;
                    string dirNm0 = tempdir + "\\data24\\" + new Random().Next(1865);
                    Directory.CreateDirectory(dirNm0);
                    CreateProcess(f0, " -CreateProfile \"webroam " + dirNm0 + "\"", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si1, out pi1);
                    TerminateProcess(pi1.hProcess, 0);
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    pi = new PROCESS_INFORMATION();
                    STARTUPINFO si = new STARTUPINFO();
                    si.lpDesktop = "WebroamDesktop";

                    string dirNm = tempdir + "\\data22\\" + new Random().Next(1865);
                    Directory.CreateDirectory(dirNm);

                    const uint NORMAL_PRIORITY_CLASS = 0x0020;
                    const uint CREATE_UNICODE_ENVIRONMENT = 0x0800;
                    const uint STARTF_USESHOWWINDOW = 0x0001;

                    si.dwX = 0;
                    si.dwY = 60;
                    si.dwXSize = 1800;
                    si.dwY = 835;
                    si.dwFlags = STARTF_USESHOWWINDOW | 2 | 1;
                    si.cb = (uint)Marshal.SizeOf(si);
                    si.wShowWindow = 3;
                            // Directory.SetCurrentDirectory("C:\\Program Files\\Internet Explorer");
                            pbox0.Click += (s0, e0) => { CreateProcess(f0, " -new-instance -P webroam -silent -private-window", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi); Task.Factory.StartNew(delegate () { Thread.Sleep(1500); panel.Invalidate(); }); };
                    pbox1.Click += async (s0, e0) => { await Task.Run(() => { ExecuteCommand(Environment.CurrentDirectory+"\\disconn.bat"); }); CreateProcess(f1, " --user-data-dir=" + dirNm + " --new-window --incognito", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi); await Task.Factory.StartNew(delegate () { panel.Invalidate(); }); await Task.Run(() => { Thread.Sleep(3500); ExecuteCommand(Environment.CurrentDirectory + "\\conn.bat"); }); };
                    pbox2.Click += (s0, e0) => { CreateProcess(f2, " -nomerge -extoff  -private about:InPrivate", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi); panel.Invalidate(); Task.Factory.StartNew(delegate () { Thread.Sleep(1500);  panel.Invalidate(); }); };

                panel.MouseDown += (s,e) => {
                    n2 = collection.Count - 1;
                    Thread.Sleep(100);
                    //SetWindowPos(loginWnd.Handle, new IntPtr(1), 0, 0, 0, 0, SetWindowPosFlags.SWP_NOMOVE | SetWindowPosFlags.SWP_NOSIZE);
                    NCForm.POINT pt = new NCForm.POINT();
                    NCForm.GetCursorPos(out pt);

                    foreach (var rr in recs)
                    {
                        if (rr.Contains(pt.x - panel.Location.X, pt.y - panel.Location.Y))
                        {
                            try
                            {
                                Thread.Sleep(100);
                                if (collection[n2].HasExited || !IsWindow(wnds[n2]))
                                    continue;
                                //ShowWindow(wnds[n2], 9);
                                //SetForegroundWindow(wnds[n2].ToInt32());
                                SetWindowPos(wnds[n2], IntPtr.Zero, 0, 0, 0, 0, SetWindowPosFlags.SWP_NOMOVE|SetWindowPosFlags.SWP_NOREPOSITION|SetWindowPosFlags.SWP_SHOWWINDOW | SetWindowPosFlags.SWP_NOSIZE);
                               // Wrecs[n2].X = 800;
                                // MessageBox.Show(""+ (int)curn.ElementAt(n2));
                                break;
                            }
                            catch { }
                        }
                        n2--;
                    }
                    int i = 0;
                   
                    var timr2 = new System.Windows.Forms.Timer();
                    timr2.Interval = 600;
                    timr2.Tick += delegate (object o51, EventArgs ee1)
                    {
                        panel.Invalidate();
                    };
                    timr2.Start();
                };
                    timr.Tick += delegate (object o5, EventArgs ee)
              {
              if ((GetKeyState(0x01) & 0x100) != 0)
              {
                      Thread.Sleep(100);
                  //SetWindowPos(loginWnd.Handle, new IntPtr(1), 0, 0, 0, 0, SetWindowPosFlags.SWP_NOMOVE | SetWindowPosFlags.SWP_NOSIZE);
                  NCForm.POINT pt = new NCForm.POINT();
                  NCForm.GetCursorPos(out pt);
                  //long _myc = Interlocked.Read(ref mycounter),
                  
                      // si.wShowWindow = 4;
                      
                      //SetWorkspace(Rect);
                     
                                     
                  }
              };
                     

                      

                      //tchk.Interval = 4500;
                      typeof(Panel).InvokeMember("DoubleBuffered", BindingFlags.SetProperty
              | BindingFlags.Instance | BindingFlags.NonPublic, null,
              panel, new object[] { true });
                          typeof(Form).InvokeMember("DoubleBuffered", BindingFlags.SetProperty
                    | BindingFlags.Instance | BindingFlags.NonPublic, null,
                    loginWnd, new object[] { true });
                          panel.Paint += Panel_Paint;
                          timr.Start();
                      //var dh0 = new DockingHelper(loginWnd.Handle.ToInt32());
                      //dh0.Subscribe();
                      var aTimer = new System.Windows.Forms.Timer();
                          aTimer.Tick += delegate (object sender, EventArgs et)
                          {
                              lbl.Text = DateTime.Now.ToShortTimeString();
                               panel.Invalidate();
                          };
                     
                // Set the Interval to 1 msecond.
                aTimer.Interval = 1000;
                              aTimer.Enabled = true;
                              aTimer.Start();
                
                SizeF scale = new SizeF(widthRatio, heightRatio);
                loginWnd.Scale(scale);
                foreach (Control control in loginWnd.Controls)
                {
                    control.Font = new Font("Verdana", control.Font.SizeInPoints * heightRatio * widthRatio);
                }
                Application.Run(loginWnd);

                          //  timer.Stop();
                    
            });
           
            tr.Start();  // waits for the task to finish
            tr.Join();
                var pall = Process.GetCurrentProcess().GetChildProcesses();
                foreach (var p1 in pall)
                {
                    p1.Kill();
                }
            SwitchDesktop(hOldDesktop);
            Resolution.CResolution ChangeRes2 = new Resolution.CResolution(tempHeight, tempWidth);
            SetWorkspace(oldRect);
            PROCESS_INFORMATION pi7 = new PROCESS_INFORMATION();
            STARTUPINFO si7 = new STARTUPINFO();
            CreateProcess(f0, " -new-instance -P default -silent -private-window", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si7, out pi7);
            TerminateProcess(pi7.hProcess, 0);
            //      foreach (var c in chrms)
            //       c.Resume();
            //   end of login form
            Clipboard.Clear();
            if (Directory.Exists(tempdir+"\\data21"))
                Directory.Delete(tempdir+"\\data21", true);
            if (Directory.Exists(tempdir+"\\data22"))
                Directory.Delete(tempdir+"\\data22", true);
            if (Directory.Exists(tempdir+"\\data24"))
                Directory.Delete(tempdir+"\\data24", true);
            // if got here, the form is closed => switch back to the old desktop
            // SwitchDesktop(hOldDesktop);

            // disposing the secure desktop since it's no longer needed
            CloseDesktop(hNewDesktop);
            ClipboardMonitor.Stop();
            }
            catch (Exception ex)
            {
               // MessageBox.Show(ex.Message);
                Application.Exit();
            }
          //  Console.WriteLine("Password, typed inside secure desktop: " + passwd);
            //Console.ReadLine();
        }

 

        private static void Panel_MouseMove(object sender, MouseEventArgs e)
        {
           // var g = panel.CreateGraphics();

            // long l = Interlocked.Read(ref mycounter);
            if (collection == null) return;
            // MessageBox.Show("");
            for (int i = 0; i < collection.Count; i++)
            {
                if (recs[i].Contains(e.Location))
                {
                    colors[i] = Color.Silver;
                    panel.Invalidate();
                    // MessageBox.Show("");
                    break;
                }
            }
           
        }
        private static List<uint> whole = new List<uint>();
        private static void Panel_Paint(object sender, PaintEventArgs e)
        {
            for (int i = 0; i < collection.Count; i++)
            {
                if (colors[i] == Color.Orange)
                {
                    colors[i] = Color.White;
                }                   
            }
            if (collection.Count > 0)
                colors[collection.Count - 1] = Color.Orange;

        
     
            //List<uint> w2 = whole.ToList();
            //
            /* */
            wnds.Clear();
           /* collection = Process.GetProcessesByName("iexplore").ToList();
            collection.AddRange(Process.GetProcessesByName("firefox"));
            collection.AddRange(Process.GetProcessesByName("chrome"));
            */
            IntPtr hnew = OpenDesktop("WebroamDesktop", 0, false, 0x00000041);
            var list = GetOpenWindows(hnew);
            uint ip = 0;
            List<Process> cl = new List<Process>();
            foreach (var l in list)
            {
                if (!IsWindowVisible(l))
                    continue;
             
                
                GetWindowThreadProcessId(l, out ip);
               
                    try
                    {
                        
                      
                        
                        StringBuilder s = new StringBuilder(50);
                        int r = GetWindowTextLength(l);
                        if(r>0)
                        GetWindowText(l, s, r);
                        if (s.ToString() != string.Empty)
                        {
                            wnds.Add(l);
                            cl.Add(Process.GetProcessById((int)ip));
                        }
                    }
                    catch { }
                
            }
        //    var cl = from c in collection join l in list on c.Id equals (int)ip select c;
            CloseDesktop(hnew);
           /* if (npp > -1)
            {
                IntPtr pw = wnds[npp];
                wnds[npp] = wnds[wnds.Count - 1];
                wnds[wnds.Count - 1] = pw;
                Process p = cl[npp];
                cl[npp] = cl[wnds.Count - 1];
                cl[wnds.Count - 1] = p;
                npp = -1;
            }*/
            collection = cl;//.OrderByDescending(x=>x.StartTime.Ticks).ToList();
           /* var curn = from w in w2
                       join c in collection
                       on (int)w equals c.Id
                       select w;
            *///List<uint> vars = curn.ToList();
          // whole = curn.ToList();
            
            int n = collection.Count;
            int vcnt = collection.Count;
            for (int i=0;i<vcnt;i++)
            {
                // e.Graphics.Clear(Color.Black);
                //long r = Interlocked.Read(ref mycounter);
            /*    try
                {
                    Process.GetProcessById((int)whole[i]).WaitForInputIdle(100);
                }
                catch
                {
                    // no graphical interface
                    continue;
                }*/
                try
                {

                     e.Graphics.DrawRectangle(new Pen(Color.Red, 2), new Rectangle((int)recs[n - 1].X, (int)recs[n - 1].Y, (int)recs[n - 1].Width, (int)recs[n - 1].Height));
                    recs[n - 1] = new RectangleF(new PointF((Wrecs[n - 1].X + pbox2.Location.X) +80+ pbox2.Width * n + (n*8), pbox2.Location.Y), new SizeF(pbox2.Width, pbox2.Height));
                   
                        e.Graphics.FillRectangle(new SolidBrush(colors[n - 1]), recs[n - 1]);
                        try
                        {

                            e.Graphics.DrawIcon(Icon.ExtractAssociatedIcon(collection[i].MainModule.FileName), (int)(recs[n - 1].X), (int)recs[n - 1].Y);
                        }
                        catch { }
                    
                }
                catch { }
              
                n--;
                
            }
        
       /*     if (colors.Contains(Color.Orange))
            {
                //Thread.Sleep(50);
            }*/
        }
         
        }
    }


