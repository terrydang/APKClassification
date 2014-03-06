using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;
using System.ComponentModel;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Visifire.Charts;
using Visifire.Commons;
using System.IO;
using System.Xml;
using System.Windows.Controls.Primitives;
using System.Collections;
using System.Threading;

namespace ApkAnalysis
{
    /// <summary>
    /// Window1.xaml 的交互逻辑
    /// </summary>
    public partial class Window1 : Window
    {
        public string aapt = System.AppDomain.CurrentDomain.BaseDirectory + "aapt.exe";
        public string apktool = System.AppDomain.CurrentDomain.BaseDirectory + "apktool.bat";
        public string permissionrule = System.AppDomain.CurrentDomain.BaseDirectory + "permissions.txt";
        public string functionrule = System.AppDomain.CurrentDomain.BaseDirectory + "functions.txt";
        public string algorithmpath = System.AppDomain.CurrentDomain.BaseDirectory + "model\\";
        public string permissionreg = @"uses-permission: (.*?)\r\n";

        private delegate void DelegateClearPanel(object panel);
        private void delegetedClearPanel(object panel)
        {
            Panel panel1 = (Panel)panel;
            panel1.Children.Clear();
        }

        private delegate void DelegateAddPanel(object parent, object child);
        private void delegatedAddPanel(object parent, object child)
        {

            Panel panel = (Panel)parent;            
            UIElement elt = (UIElement)child;           
            panel.Children.Add(elt);

        }

        private delegate bool DelegateReadCheckBox(CheckBox checkbox);
        private bool delegatedReadCheckBox(CheckBox checkbox)
        {
            try
            {
                if (checkbox.IsChecked == true)
                {
                    return true;
                }
                else 
                {
                    return false;
                }
            }
            catch 
            {
                return false;
            }
        }

        public Window1()
        {
            InitializeComponent();            
            //CreateChart();
        }

        private void button1_Click(object sender, RoutedEventArgs e)
        {
            
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Multiselect = false;
            ofd.Title = "请选择APK文件";
            ofd.Filter = "apk文件(*.apk)|*.apk";
            ofd.ShowDialog();
            textBox1.Text = ofd.FileName;

            AnalyzeAll(ofd.FileName);
            /*
            Thread thread = new Thread(new ParameterizedThreadStart(AnalyzeThread));
            thread.SetApartmentState(ApartmentState.STA);
            thread.IsBackground = true;
            thread.Start(ofd.FileName);
            */
            //new WekaSharp().Test2();
            
        }

        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left) this.DragMove();
        }

        private void button2_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void AnalyzeThread(object filename)
        {
            string strfilename = filename.ToString();
            AnalyzeAll(strfilename);
        }       

        private bool DumpAPK(string apkfile, string path)
        {
            bool ret = false;
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path,true);
                }
                Process process = new Process();
                process.StartInfo.FileName = apktool;
                process.StartInfo.Arguments = "d \"" + apkfile + "\" \"" + path + "\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardInput = true;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit(30000);
                //string str = process.StandardOutput.ReadToEnd();
                //string err = process.StandardError.ReadToEnd();
                if(!process.HasExited)
                {
                    process.Kill();
                    return false;
                }                
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool GetPermissonsAndReceivers(string filename, ref List<string> permissionList, ref List<string> receiverList)
        {            
            try
            {               
                string tmppath = System.AppDomain.CurrentDomain.BaseDirectory + "tmp";
                if (DumpAPK(filename, tmppath) == false)                
                {                    
                    return false;
                }

                //read AndroidManifest.xml
                string xmlfile = tmppath + "\\AndroidManifest.xml";
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(xmlfile);

                XmlNode manifest = xmldoc.SelectSingleNode("manifest");
                //read permissions
                XmlNodeList permissionNodes = manifest.SelectNodes("uses-permission");
                if (permissionNodes.Count > 0)
                {
                    foreach (XmlNode permissionNode in permissionNodes)
                    {
                        string permission = permissionNode.Attributes["android:name"].Value;
                        if (!permissionList.Contains(permission))
                        {
                            permissionList.Add(permission);
                        }                       
                    }
                }
               
                //read receiver               

                XmlNode applicationNode = manifest.SelectSingleNode("application");
                XmlNodeList receiverNodes = applicationNode.SelectNodes("receiver");
                if (receiverNodes.Count > 0)
                {
                    foreach (XmlNode receiverNode in receiverNodes)
                    {
                        string receiverName = receiverNode.Attributes["android:name"].Value;
                        //intent-filter
                        XmlNode intentNode = receiverNode.SelectSingleNode("intent-filter");
                        string priority = "0";
                        try
                        {
                            priority = intentNode.Attributes["priority"].Value;
                        }
                        catch { }
                        string receiverDesp = receiverName + "," + priority;
                        if (!receiverList.Contains(receiverDesp))
                        {
                            receiverList.Add(receiverDesp);
                        }

                    }
                }
                return true;

            }
            catch (Exception err)
            {
                return false;
            }

        }

        private void SearchFunction(ref List<string> functionList)
        {
            ArrayList fileList = new ArrayList();
            string tmppath = System.AppDomain.CurrentDomain.BaseDirectory + "tmp\\smali";
            FileAccess fa = new FileAccess();
            fileList = fa.GetAllFileName(tmppath);
            if (fileList.Count == 0)
            {
                return;
            }

            List<Threat> functionRuleList = LoadFunctionRules();
            if (functionRuleList.Count == 0)
            {
                return;
            }

            foreach(string filename in fileList)
            {
                try
                {
                    StreamReader sr = new StreamReader(filename);
                    string content = sr.ReadToEnd();
                    sr.Close();
                    foreach (Threat threat in functionRuleList)
                    {                        
                        if(content.Contains(threat.name))
                        {
                            string funcDesp = threat.name + "," + threat.value;
                            if (!functionList.Contains(funcDesp))
                            {
                                functionList.Add(funcDesp);
                            }
                        }
                    }
                }
                catch { }
            
            }

            //read AndroidManifest.xml
            string xmlfile = tmppath + "\\AndroidManifest.xml";
        }

        private List<Threat> LoadFunctionRules()
        {
            List<Threat> retList = new List<Threat>();
            StreamReader sr = new StreamReader(functionrule);
            while (sr.Peek() > 0)
            {
                string str = sr.ReadLine();
                try
                {
                    string func = str.Split(',')[0];
                    string value = str.Split(',')[1];
                    Threat threat = new Threat(func,int.Parse(value));
                    retList.Add(threat);
                }
                catch { }
            }
            sr.Close();
            return retList;
        }
      

        private void AnalyzeAll(string filename)
        {
            try
            {
                //panel1.Children.Clear();
                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateClearPanel(delegetedClearPanel),panel1);             


                List<string> permissionList = new List<string>();
                List<string> receiverList = new List<string>();
                List<string> functionList = new List<string>();
                if (GetPermissonsAndReceivers(filename, ref permissionList, ref receiverList) == false)
                {
                    TextBlock tb = new TextBlock();
                    tb.Text = "No Result!";
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle,new DelegateAddPanel(delegatedAddPanel), panel1,tb);
                   // panel1.Children.Add(tb);
                    return;
                }

                UIElementCollection uis = panel_al.Children;
                for (int i = 0; i < uis.Count; i++)
                {
                    try
                    {
                        CheckBox checkbox = (CheckBox)uis[i];
                        if (checkbox.IsChecked == true)
                        {
                            WekaAnalysis(permissionList, checkbox.Name.Substring(3));
                        }
                    }
                    catch { }
                }
                

                /*

                if (checkBox_J48.IsChecked==true)
                //if((bool)Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, 
                //        new DelegateReadCheckBox(delegatedReadCheckBox), checkBox_J48)==true)
                {
                    WekaAnalysis(permissionList, "J48");
                }
                if (checkBox_BayesNet.IsChecked == true)
                //if ((bool)Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle,
                //        new DelegateReadCheckBox(delegatedReadCheckBox), checkBox_BayesNet) == true)
                {
                    WekaAnalysis(permissionList, "NaiveBayes");
                }
                if (checkBox_Som.IsChecked == true)
                //if((bool)Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, 
                //        new DelegateReadCheckBox(delegatedReadCheckBox), checkBox_Som)==true)
                {
                    WekaAnalysis(permissionList, "som");
                }
                if (checkBox_Id3.IsChecked == true)
                //if ((bool)Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle,
                //        new DelegateReadCheckBox(delegatedReadCheckBox), checkBox_Id3) == true)
                {
                    WekaAnalysis(permissionList, "Id3");
                }
                if (checkBox_DecisionTable.IsChecked == true)
                //if ((bool)Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle,
                //        new DelegateReadCheckBox(delegatedReadCheckBox), checkBox_DecisionTable) == true)
                {
                    WekaAnalysis(permissionList, "DecisionTable");
                }
               */
               

                if (permissionList.Count > 0)
                {
                    //PermissionAnalysis(permissionList);

                    StackPanel sp1 = new StackPanel();
                    sp1.Orientation = Orientation.Horizontal;
                    TextBlock tb1 = new TextBlock();
                    tb1.Width = 500;
                    tb1.Text = "Permission";
                    TextBlock tb2 = new TextBlock();
                    tb2.Text = "Threat";
                    sp1.Children.Add(tb1);
                    sp1.Children.Add(tb2);
                    //panel1.Children.Add(sp1);
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, sp1);
                    //panel1.Children.Add(new Separator());
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, new Separator());
                    
                    foreach (string permission in permissionList)
                    {
                        int threat = GetThreatValue(permission);
                       
                        StackPanel sp = new StackPanel();
                        sp.Orientation = Orientation.Horizontal;
                        TextBlock tbpermission = new TextBlock();
                        tbpermission.Width = 500;
                        tbpermission.Text = permission;
                        Image impermission = new Image();
                        impermission.Source = (ImageSource)new ImageSourceConverter().
                            ConvertFrom(AppDomain.CurrentDomain.BaseDirectory + "Resource\\level" + threat + ".gif");                    
                        sp.Children.Add(tbpermission);
                        sp.Children.Add(impermission);
                        Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle,new DelegateAddPanel(delegatedAddPanel), panel1, sp);
                        //panel1.Children.Add(sp);
                    }
                    //panel1.Children.Add(new TextBlock());
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, new TextBlock());
                }

                if (receiverList.Count > 0)
                {
                    StackPanel sp1 = new StackPanel();
                    sp1.Orientation = Orientation.Horizontal;
                    TextBlock tb1 = new TextBlock();
                    tb1.Width = 500;
                    tb1.Text = "Receivers";
                    TextBlock tb2 = new TextBlock();
                    tb2.Text = "Threat";
                    sp1.Children.Add(tb1);
                    sp1.Children.Add(tb2);
                    //panel1.Children.Add(sp1);
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, sp1);
                    //panel1.Children.Add(new Separator());
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle,new DelegateAddPanel(delegatedAddPanel), panel1, new Separator());

                    foreach (string receiver in receiverList)
                    {
                        string receiverName = receiver.Split(',')[0];
                        string priority = receiver.Split(',')[1];
                        int threat = GetThreatValue("priority:" + priority);

                        StackPanel sp = new StackPanel();
                        sp.Orientation = Orientation.Horizontal;
                        TextBlock tbpermission = new TextBlock();
                        tbpermission.Width = 500;
                        tbpermission.Text = receiverName;
                        Image impermission = new Image();
                        impermission.Source = (ImageSource)new ImageSourceConverter().
                            ConvertFrom(AppDomain.CurrentDomain.BaseDirectory + "Resource\\level" + threat + ".gif");
                        sp.Children.Add(tbpermission);
                        sp.Children.Add(impermission);
                        Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, sp);
                        //panel1.Children.Add(sp);
                    }
                    //panel1.Children.Add(new TextBlock());
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, new TextBlock());
                }

                SearchFunction(ref functionList);
                if (functionList.Count > 0)
                {
                    StackPanel sp1 = new StackPanel();
                    sp1.Orientation = Orientation.Horizontal;
                    TextBlock tb1 = new TextBlock();
                    tb1.Width = 500;
                    tb1.Text = "Functions";
                    TextBlock tb2 = new TextBlock();
                    tb2.Text = "Threat";
                    sp1.Children.Add(tb1);
                    sp1.Children.Add(tb2);
                    //panel1.Children.Add(sp1);
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, sp1);
                    //panel1.Children.Add(new Separator());
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, new Separator());

                    foreach (string func in functionList)
                    {
                        string funcName = func.Split(',')[0];
                        int threat = int.Parse(func.Split(',')[1]);                     

                        StackPanel sp = new StackPanel();
                        sp.Orientation = Orientation.Horizontal;
                        TextBlock tbpermission = new TextBlock();
                        tbpermission.Width = 500;
                        tbpermission.Text = funcName;
                        Image impermission = new Image();
                        impermission.Source = (ImageSource)new ImageSourceConverter().
                            ConvertFrom(AppDomain.CurrentDomain.BaseDirectory + "Resource\\level" + threat + ".gif");
                        sp.Children.Add(tbpermission);
                        sp.Children.Add(impermission);
                        Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, sp);
                       //panel1.Children.Add(sp);
                    }
                    //panel1.Children.Add(new TextBlock());
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.SystemIdle, new DelegateAddPanel(delegatedAddPanel), panel1, new TextBlock());
                }  
                 

               
               
            }
            catch(Exception err)
            {
                MessageBox.Show(err.Message);
            }

        }

        private void PermissionAnalysis(List<string> permissionList)
        {
            try
            {
                List<Threat> threatList = new List<Threat>();
                foreach (string permission in permissionList)
                {
                    int threatvalue = GetThreatValue(permission);
                    Threat threat = new Threat(permission.Replace("android.permission.",""), threatvalue);
                    threatList.Add(threat);
                }
                threatList.Sort(new ThreatResultComparer());
                //Draw
                //////////////////////////////////////           
                Chart chart = new Chart();
                chart.View3D = true;                           
                Title title = new Title();
                title.Text = "Permission Threats";
                chart.Titles.Add(title);
                chart.ColorSet = "VisiRed";                
                //X坐标
                Axis xaxis = new Axis();
                AxisLabels xal = new AxisLabels
                {
                    Enabled = true,
                    Angle = 0

                };
                xaxis.AxisLabels = xal;
                // Y坐标
                Axis yaxis = new Axis();
                AxisLabels yal = new AxisLabels
                {
                    Enabled = true,
                    Angle = 0
                };
                yaxis.AxisLabels = yal;
                yaxis.Suffix = "/10";

                chart.AxesX.Add(xaxis);
                chart.AxesY.Add(yaxis);

                DataSeries dataSeries = new DataSeries();
                dataSeries.RenderAs = RenderAs.Bar;

                foreach (Threat threat in threatList)
                {
                    DataPoint dataPoint = new DataPoint { AxisXLabel = threat.name, YValue = threat.value };
                    dataSeries.DataPoints.Add(dataPoint);
                    //dataSeries.ShowInLegend = true;                    
                }
                chart.Series.Add(dataSeries);
                Grid grid = new Grid();
                grid.Height = 250;
                grid.Children.Add(chart);
                panel1.Children.Add(grid);
            }
            catch
            {
            }
            
            
        }

        private void WekaAnalysis(List<string> permissionList,string modelname)
        {
            List<string> wekaret = new List<string>();
            string tmparff = System.AppDomain.CurrentDomain.BaseDirectory + "tmp.arff";
            string J48model = algorithmpath + modelname + ".model";
            try
            {                
                WekaSharp WS = new WekaSharp();
                WS.GenerateARFF(permissionList, tmparff);
                wekaret = WS.Classify(J48model, tmparff);                
                if (wekaret.Count == 0)
                {
                    return;
                }
                //转成ClassifyResult型
                List<ClassifyResult> result = new List<ClassifyResult>();
                foreach (string wekadata in wekaret)
                {
                    string[] strs = wekadata.Split(',');
                    string classname = strs[0];
                    double value = double.Parse(strs[1]);
                    ClassifyResult cr = new ClassifyResult(classname, value);
                    result.Add(cr);
                }
                result.Sort(new ClassifyResultComparer());

                //Draw
                //////////////////////////////////////           
                Chart chart = new Chart();
                chart.View3D = true;                
                //chart.ColorSet = "Picasso";                
                Title title = new Title();
                title.Text = "Classify: " + modelname;
                chart.Titles.Add(title);
                //X坐标
                Axis xaxis = new Axis();
                AxisLabels xal = new AxisLabels
                {
                    Enabled = true,                    
                    Angle = 0
                    
                };                
                xaxis.AxisLabels = xal;
                // Y坐标
                Axis yaxis = new Axis();
                AxisLabels yal = new AxisLabels
                {
                    Enabled = true,
                    Angle = 0
                };
                yaxis.AxisLabels = yal;
                yaxis.Suffix = "%";

                chart.AxesX.Add(xaxis);
                chart.AxesY.Add(yaxis);

                DataSeries dataSeries = new DataSeries();
                dataSeries.RenderAs = RenderAs.Pie;                

                foreach(ClassifyResult cr in result)                
                {
                    if (cr.value > 0)
                    {
                        DataPoint dataPoint = new DataPoint { AxisXLabel = cr.name, YValue = cr.value * 100 };
                        dataSeries.DataPoints.Add(dataPoint);
                    }                                      
                }
                chart.Series.Add(dataSeries);
                Grid grid = new Grid();
                grid.Height = 250;
                grid.Children.Add(chart);
                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal, new DelegateAddPanel(delegatedAddPanel), panel1, grid);
                //panel1.Children.Add(grid);
            }
            catch 
            {                
            }
        }

        private int GetThreatValue(string input)
        {
            int ret = 1;
            try
            {
                if(input.StartsWith("priority:"))
                {
                    int priority = int.Parse(input.Replace("priority:", ""));
                    if (priority > 100)
                    {
                        return 8;
                    }
                    else
                    {
                        return 5;
                    }
                }

                StreamReader sr = new StreamReader(permissionrule);
                while (sr.Peek()>0)
                {
                    string str = sr.ReadLine();
                    try
                    {
                        string permission = str.Split(',')[0];
                        string value = str.Split(',')[1];
                        if (String.Compare(input, permission, true) == 0)
                        {
                            return int.Parse(value);
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
                sr.Close();
            }
            catch
            {}            
            return ret;
        }

        private void button3_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            InitAlgorithm();
        }

        private void InitAlgorithm()
        {
            try
            {
                List<string> algorithms = new List<string>();
                DirectoryInfo di = new DirectoryInfo(algorithmpath);
                FileInfo[] fis = di.GetFiles();
                for (int i = 0; i < fis.Length; i++)
                {
                    FileInfo fi = fis[i];
                    string filename = fi.Name;
                    if (filename.EndsWith(".model"))
                    {
                        string algorithm = System.IO.Path.GetFileNameWithoutExtension(filename);
                        if (!algorithms.Contains(algorithm))
                        {
                            algorithms.Add(algorithm);
                        }
                    }
                }

                if (algorithms.Count == 0)
                {
                    return;
                }

                //StackPanel sp = new StackPanel();
                //sp.Name = "panel_algorithm";
                //sp.Orientation = Orientation.Horizontal;
                //sp.CanHorizontallyScroll = true;
                foreach (string al in algorithms)
                {
                    CheckBox checkbox = new CheckBox();
                    checkbox.Name = "cb_" + al;
                    checkbox.Content = al + "  ";
                    //sp.Children.Add(checkbox);
                    panel_al.Children.Add(checkbox);
                }
                //panel1.Children.Add(sp);

            }
            catch
            {
                MessageBox.Show("初始化失败");
            }
        }

    }

    public class Threat
    {
        public string name;
        public int value;
        public Threat(string name, int value)
        {
            this.name = name;
            this.value = value;
        }
    }

    public class ThreatResultComparer : IComparer<Threat>
    {
        public int Compare(Threat x, Threat y)
        {
            return x.value.CompareTo(y.value);
        }
    }

    public class ClassifyResult
    {
        public string name;
        public double value;
        public ClassifyResult(string name, double value)
        {
            this.name = name;
            this.value = value;
        }
    }

    public class ClassifyResultComparer:IComparer<ClassifyResult>
    {
        public int Compare(ClassifyResult x, ClassifyResult y)
        {
            return -x.value.CompareTo(y.value);
        }
    }
}
