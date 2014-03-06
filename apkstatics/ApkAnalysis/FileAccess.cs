using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Data;
using System.Collections;

namespace ApkAnalysis
{
    public class FileAccess
    {
       
        //储存所有文件夹名
        private ArrayList dirs;
        public FileAccess()
        {
            dirs = new ArrayList();
        }
        //获取所有文件名
        private ArrayList GetFileName(string dirPath)
        {
            ArrayList list = new ArrayList();
            if (Directory.Exists(dirPath))
            {
                list.AddRange(Directory.GetFiles(dirPath));
            }
            return list;
        }
        //获取所有文件夹及子文件夹
        private void GetDirs(string dirPath)
        {
            if (Directory.GetDirectories(dirPath).Length > 0)
            {
                foreach (string path in Directory.GetDirectories(dirPath))
                {
                    dirs.Add(path);
                    GetDirs(path);
                }
            }
        }
        /// <summary>
        /// 获取给出文件夹及其子文件夹下的所有文件名
        /// （文件名为路径加文件名及后缀,
        /// 使用的时候GetAllFileName().ToArray()方法可以转换成object数组
        /// 之后再ToString()分别得到文件名）
        /// </summary>
        /// <param name="rootPath">文件夹根目录</param>
        /// <returns></returns>
        public ArrayList GetAllFileName(string rootPath)
        {
            dirs.Add(rootPath);
            GetDirs(rootPath);
            object[] allDir = dirs.ToArray();
            ArrayList list = new ArrayList();
            foreach (object o in allDir)
            {
                list.AddRange(GetFileName(o.ToString()));
            }
            return list;
        }
        /// <summary>
        /// 如果上个方法不知道怎么用，那就调用这个方法吧
        /// </summary>
        /// <param name="rootPath"></param>
        /// <returns></returns>
        public List<string> FileName(string rootPath)
        {
            List<string> list = new List<string>();
            foreach (object o in GetAllFileName(rootPath).ToArray())
            {
                list.Add(o.ToString());
            }
            return list;
        }
    }
}
