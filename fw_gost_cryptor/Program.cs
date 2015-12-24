using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace fw_gost_cryptor
{
	class Program
	{
		[STAThread]
		static void Main(string[] args)
		{
			Console.Title = "Gost 28147-89 Cryptor";
			Console.ForegroundColor = ConsoleColor.Cyan;
			Console.BackgroundColor = ConsoleColor.DarkBlue;
			Console.Clear();
			Console.WriteLine("Welcom! \r\n");

			string fileName = "";
			string key = "";
			byte[] inputData;

			FileCommander fileCommander = new FileCommander();
			Gost28147_89 gost28147_89 = new Gost28147_89();
			OpenFileDialog openFileDialog = new OpenFileDialog();
			XmlFileCommander xmlFileCommander = new XmlFileCommander();

			if (openFileDialog.ShowDialog() == DialogResult.OK)
			{
				gost28147_89.kboxinit();
				gost28147_89.ReadKey();

				fileName = openFileDialog.FileName;

				Console.WriteLine("Pess \"C\" for crypt file \r\n");
				Console.WriteLine("Pess \"D\" for decrypt file \r\n");

				ConsoleKeyInfo cki = Console.ReadKey();
				if (cki.KeyChar == 'c')										//Если нажата кнопка "C"
				{
					inputData = fileCommander.ReadFile(fileName);
					byte[] outputData = gost28147_89.gostDataCrypt(inputData);

					xmlFileCommander.WriteXml(outputData, fileCommander.OutputFileName);
				
					Console.Beep();
					for (int i = 0; i < gost28147_89.Key.Length; i++)
					{
						key += (gost28147_89.Key[i]).ToString() + " \r\n ";
					}
					Console.WriteLine("Key: \r\n {0}", key);
					Console.WriteLine("File size is: {0} bytes", fileCommander.FileSize);
					Console.WriteLine("CRC16 is: {0}", CRC.crc16(outputData, outputData.Length));
					Console.WriteLine("Crypted file saved: {0}", fileCommander.OutputFileName);
					Console.ReadKey();
				}
				else if (cki.KeyChar == 'd')							//Если нажата кнопка "C"
				{
					inputData = fileCommander.ReadFile(fileName);
					inputData = xmlFileCommander.ReadXml(fileName, "data");
					byte[] outputData = gost28147_89.gostDataDecrypt(inputData);

					fileCommander.WriteFile(outputData);

					Console.Beep();
					for (int i = 0; i < gost28147_89.Key.Length; i++)
					{
						key += (gost28147_89.Key[i]).ToString() + " \r\n ";
					}
					Console.WriteLine("Key: \r\n {0}", key);
					Console.WriteLine("File size is: {0} bytes", fileCommander.FileSize);
					Console.WriteLine("CRC16 is: {0}", CRC.crc16(outputData, outputData.Length));
					Console.WriteLine("Crypted file saved: {0}", fileCommander.OutputFileName);
					Console.ReadKey();
				}
				else
				{
					Console.WriteLine("Error symbol");
					Console.ReadKey();
				}
			}
		}
	}
}
