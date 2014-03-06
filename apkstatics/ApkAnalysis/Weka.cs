using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;


namespace ApkAnalysis
{
    class WekaSharp
    {
        string arfftemplate = System.AppDomain.CurrentDomain.BaseDirectory + "arff.txt";

        public void Test()
        {
            weka.core.Instances insts = new weka.core.Instances(new java.io.FileReader("D:\\android_analysis\\attributes.arff"));
            insts.setClassIndex(insts.numAttributes() - 1);

            weka.classifiers.Classifier cl = new weka.classifiers.trees.J48();
            cl.buildClassifier(insts);
            weka.filters.Filter myRandom = new weka.filters.unsupervised.instance.Randomize();
            myRandom.setInputFormat(insts);
            insts = weka.filters.Filter.useFilter(insts, myRandom);

            int trainSize = (int)(insts.numInstances() * 0.66);
            int testSize = insts.numInstances() - trainSize;
            weka.core.Instances train = new weka.core.Instances(insts, 0, trainSize);

            cl.buildClassifier(train);
            for (int i = trainSize; i < insts.numInstances(); i++)
            {
                weka.core.Instance currentInst = insts.instance(i);
                double predictedClass = cl.classifyInstance(currentInst);
                double[] distrs = cl.distributionForInstance(currentInst);
                string actual = insts.classAttribute().value((int)currentInst.classValue());
                string predicted = insts.classAttribute().value((int)predictedClass);
                System.Console.WriteLine("ID: " + (i+1) + ", " + actual + " --> " + predicted);
            }

        }

        public void Test2()
        {    
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.FileInputStream("D:\\android_analysis\\som_model.model"));            
            weka.classifiers.Classifier cl = (weka.classifiers.Classifier)ois.readObject();
            ois.close();

            weka.core.Instances insts = new weka.core.Instances(new java.io.FileReader("D:\\android_analysis\\test1.arff"));
            insts.setClassIndex(insts.numAttributes() - 1);
            for (int i = 0; i < insts.numInstances(); i++)
            {
                weka.core.Instance currentInst = insts.instance(i);
                double predictedClass = cl.classifyInstance(currentInst);
                double[] distrs = cl.distributionForInstance(currentInst);
                //string actual = insts.classAttribute().value((int)currentInst.classValue());
                //string predicted = insts.classAttribute().value((int)predictedClass);
               // System.Console.WriteLine("ID: " + (i + 1) + ", " + predicted);
            }
        }

        public void GenerateARFF(List<string> permissionList,string outputfile)
        {
            List<string> attributes = new List<string>();
            try
            {
                StreamReader sr = new StreamReader(arfftemplate);
                //Load Attributes
                while (sr.Peek() > 0)
                {
                    string line = sr.ReadLine();
                    if (line.StartsWith("@attribute"))
                    {
                        int index1 = line.IndexOf("\'");
                        int index2 = line.Substring(index1 + 1).IndexOf("\'");
                        string attribute = line.Substring(index1+1,index2);
                        if (attribute != "CLASS")
                        {
                            attributes.Add(attribute);
                        }
                    }
                }
                sr.Close();

                //Calculate data
                List<string> datas = new List<string>();
                for (int i = 0; i < attributes.Count; i++)
                {
                    datas.Add("0");
                }                

                foreach (string permission in permissionList)
                {
                    string str = permission.Replace("android.permission.", "");
                    int index = attributes.FindIndex(name =>
                        {
                            if (name == str)
                            {
                                return true;
                            }
                            return false;
                        });
                    if(index>=0)
                    {
                        datas[index] = "1";
                    }
                }
                //Write File
                File.Copy(arfftemplate, outputfile, true);
                StreamWriter sw = new StreamWriter(outputfile,true);
                foreach (string data in datas)
                {
                    sw.Write(data + ",");
                }
                sw.Write("?");
                sw.Close();
            }
            catch { }
        }

        public List<string> Classify(string model, string test)
        {
            List<string> ret = new List<string>();
            try
            {
                java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.FileInputStream(model));
                weka.classifiers.Classifier cl = (weka.classifiers.Classifier)ois.readObject();
                ois.close();

                weka.core.Instances insts = new weka.core.Instances(new java.io.FileReader(test));
                insts.setClassIndex(insts.numAttributes() - 1);
                for (int i = 0; i < 1; i++)
                {
                    weka.core.Instance currentInst = insts.instance(i);
                    double predictedClass = cl.classifyInstance(currentInst);
                    double[] distrs = cl.distributionForInstance(currentInst);
                    //string actual = insts.classAttribute().value((int)currentInst.classValue());
                    //string predicted = insts.classAttribute().value((int)predictedClass);
                    // System.Console.WriteLine("ID: " + (i + 1) + ", " + predicted);
                    for (int j = 0; j < distrs.Length; j++)
                    {
                        string predicted = insts.classAttribute().value(j);
                        string distr = distrs[j].ToString("#0.000");
                        ret.Add(predicted + "," + distr);
                    }
                }
                return ret;
            }
            catch
            {
                return ret;
            }
            
        }
    }
}
