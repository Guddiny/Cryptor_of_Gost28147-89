using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace fw_gost_cryptor
{
	public class FileCommander
	{
		// Private variable
		private string inputFileName = "";
		private string outputFileName = "";
		private uint fileSize = 0;

		// geters and setters
		public string InputFileName
		{
			get { return inputFileName; }
		}

		public string OutputFileName
		{
			get { return outputFileName; }
			set { outputFileName = value; }
		}

		public uint FileSize
		{
			get { return fileSize; }
		}

		/// <summary>
		/// Read file in narray of byte
		/// </summary>
		/// <param name="fileName"></param>
		/// <returns></returns>
		public byte[] ReadFile(string fileName)
		{
			inputFileName = fileName;
			byte[] data;
			FileStream fileReadStream = null;

			try
			{
				fileReadStream = new FileStream(@fileName, FileMode.Open);
				data = new byte[fileReadStream.Length];
				fileSize = (uint)fileReadStream.Length;
				fileReadStream.Read(data, 0, data.Length);
				if (inputFileName.Contains("-crypted"))
				{
					outputFileName = inputFileName.Replace("-crypted", "-uncrypted");
				}
				else
				{
					outputFileName = inputFileName.Insert(inputFileName.Length - 4, "-crypted");
				}
			}
			catch (Exception)
			{
				data = new byte[] { 0 };
				Console.WriteLine("The target file not found, or bad file name");
			}
			finally
			{
				if (fileReadStream != null)
					fileReadStream.Close();
			}
			return data;
		}

		/// <summary>
		/// Create and save encrypted file
		/// </summary>
		/// <param name="data"></param>
		public void WriteFile(byte[] data)
		{
			FileStream fileWriteStream = null;
			try
			{
				fileWriteStream = new FileStream(@outputFileName, FileMode.OpenOrCreate);
				fileWriteStream.Write(data, 0, data.Length);
			}
			catch (Exception)
			{
				Console.WriteLine("Error create encrypted file.");
			}
			finally
			{
				if (fileWriteStream != null)
					fileWriteStream.Close();
			}
		}
	}
}
