using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

/*
 * The GOST 28147-89 cipher
 *
 * This is based on the 25 Movember 1993 draft translation
 * by Aleksandr Malchik, with Whitfield Diffie, of the Government
 * Standard of the U.S.S.R. GOST 28149-89, "Cryptographic Transformation
 * Algorithm", effective 1 July 1990.  (Whitfield.Diffie@eng.sun.com)
 *
 * That is a draft, and may contain errors, which will be faithfully
 * reflected here, along with possible exciting new bugs.
 *
 * Some details have been cleared up by the paper "Soviet Encryption
 * Algorithm" by Josef Pieprzyk and Leonid Tombak of the University
 * of Wollongong, New South Wales.  (josef/leo@cs.adfa.oz.au)
 *
 * The standard is written by A. Zabotin (project leader), G.P. Glazkov,
 * and V.B. Isaeva.  It was accepted and introduced into use by the
 * action of the State Standards Committee of the USSR on 2 June 89 as
 * No. 1409.  It was to be reviewed in 1993, but whether anyone wishes
 * to take on this obligation from the USSR is questionable.
 *
 * This code is placed in the public domain.
 */

/*
 * If you read the standard, it belabors the point of copying corresponding
 * bits from point A to point B quite a bit.  It helps to understand that
 * the standard is uniformly little-endian, although it numbers bits from
 * 1 rather than 0, so bit n has value 2^(n-1).  The least significant bit
 * of the 32-bit words that are manipulated in the algorithm is the first,
 * lowest-numbered, in the bit string.
 */

namespace fw_gost_cryptor
{
	class Gost28147_89
	{
		 /*
		 * The standard does not specify the contents of the 8 4 bit->4 bit
		 * substitution boxes, saying they're a parameter of the network
		 * being set up.  For illustration purposes here, I have used
		 * the first rows of the 8 S-boxes from the DES.  (Note that the
		 * DES S-boxes are numbered starting from 1 at the msb.  In keeping
		 * with the rest of the GOST, I have used little-endian numbering.
		 * Thus, k8 is S-box 1.
		 *
		 * Obviously, a careful look at the cryptographic properties of the cipher
		 * must be undertaken before "production" substitution boxes are defined.
		 *
		 * The standard also does not specify a standard bit-string representation
		 * for the contents of these blocks.
		 */
		private readonly byte[] k8 = { 0x14, 0x40, 0x13, 0x01, 0x02, 0x15, 0x11, 0x08, 0x03, 0x10, 0x06, 0x12, 0x05, 0x09, 0x00, 0x07 };
		private readonly byte[] k7 = { 0x15, 0x01, 0x08, 0x14, 0x06, 0x11, 0x03, 0x04, 0x09, 0x07, 0x02, 0x13, 0x12, 0x00, 0x05, 0x10 };
		private readonly byte[] k6 = { 0x10, 0x00, 0x09, 0x14, 0x06, 0x03, 0x15, 0x05, 0x01, 0x13, 0x12, 0x07, 0x11, 0x04, 0x02, 0x08 };
		private readonly byte[] k5 = { 0x07, 0x13, 0x14, 0x03, 0x00, 0x06, 0x09, 0x10, 0x01, 0x02, 0x08, 0x05, 0x11, 0x12, 0x04, 0x15 };
		private readonly byte[] k4 = { 0x02, 0x12, 0x04, 0x01, 0x07, 0x10, 0x11, 0x06, 0x08, 0x05, 0x03, 0x15, 0x13, 0x00, 0x14, 0x09 };
		private readonly byte[] k3 = { 0x12, 0x01, 0x10, 0x15, 0x09, 0x02, 0x06, 0x08, 0x00, 0x13, 0x03, 0x04, 0x14, 0x07, 0x05, 0x11 };
		private readonly byte[] k2 = { 0x04, 0x11, 0x02, 0x14, 0x15, 0x00, 0x08, 0x13, 0x03, 0x12, 0x09, 0x07, 0x05, 0x10, 0x06, 0x01 };
		private readonly byte[] k1 = { 0x13, 0x02, 0x08, 0x04, 0x06, 0x15, 0x11, 0x01, 0x10, 0x09, 0x03, 0x14, 0x05, 0x00, 0x12, 0x07 };

		private byte[] k87 = new byte[256];
		private byte[] k65 = new byte[256];
		private byte[] k43 = new byte[256];
		private byte[] k21 = new byte[256];

		public void kboxinit()
		{
			int i;
			for (i = 0; i < 256; i++) 
			{
			k87[i] = (byte)(k8[i >> 4] << 4 | k7[i & 15]);
			k65[i] = (byte)(k6[i >> 4] << 4 | k5[i & 15]);
			k43[i] = (byte)(k4[i >> 4] << 4 | k3[i & 15]);
			k21[i] = (byte)(k2[i >> 4] << 4 | k1[i & 15]);
			}
		}

		 /*
		 * Do the substitution and rotation that are the core of the operation,
		 * like the expansion, substitution and permutation of the DES.
		 * It would be possible to perform DES-like optimisations and store
		 * the table entries as 32-bit words, already rotated, but the
		 * efficiency gain is questionable.
		 *
		 * This should be inlined for maximum speed
		 */
		private uint rot(uint x)
		{
			/* Do substitutions */
			/* This is faster */
			x = (uint)(k87[x >> 24 & 255] << 24 | k65[x >> 16 & 255] << 16 |
					k43[x >> 8 & 255] << 8 | k21[x & 255]);
			/* Rotate left 11 bits */
			return x << 11 | x >> (32 - 11);
		}

		public void gostcrypt(uint[] input, uint[] output, uint[] key)
		{
			uint n1, n2; /* As named in the GOST */

			n1 = input[0];
			n2 = input[1];

			/* Instead of swapping halves, swap names each round */
			n2 ^= rot(n1+key[0]);
			n1 ^= rot(n2+key[1]);
			n2 ^= rot(n1+key[2]);
			n1 ^= rot(n2+key[3]);
			n2 ^= rot(n1+key[4]);
			n1 ^= rot(n2+key[5]);
			n2 ^= rot(n1+key[6]);
			n1 ^= rot(n2+key[7]);

			n2 ^= rot(n1+key[0]);
			n1 ^= rot(n2+key[1]);
			n2 ^= rot(n1+key[2]);
			n1 ^= rot(n2+key[3]);
			n2 ^= rot(n1+key[4]);
			n1 ^= rot(n2+key[5]);
			n2 ^= rot(n1+key[6]);
			n1 ^= rot(n2+key[7]);

			n2 ^= rot(n1+key[0]);
			n1 ^= rot(n2+key[1]);
			n2 ^= rot(n1+key[2]);
			n1 ^= rot(n2+key[3]);
			n2 ^= rot(n1+key[4]);
			n1 ^= rot(n2+key[5]);
			n2 ^= rot(n1+key[6]);
			n1 ^= rot(n2+key[7]);

			n2 ^= rot(n1+key[7]);
			n1 ^= rot(n2+key[6]);
			n2 ^= rot(n1+key[5]);
			n1 ^= rot(n2+key[4]);
			n2 ^= rot(n1+key[3]);
			n1 ^= rot(n2+key[2]);
			n2 ^= rot(n1+key[1]);
			n1 ^= rot(n2+key[0]);

			/* There is no swap after the last round */
			output[0] = n2;
			output[1] = n1;
		}

		public void gostdecrypt(uint[] input, uint[] output, uint[] key)
		{
			uint n1, n2; /* As named in the GOST */

			n1 = input[0];
			n2 = input[1];

			n2 ^= rot(n1+key[0]);
			n1 ^= rot(n2+key[1]);
			n2 ^= rot(n1+key[2]);
			n1 ^= rot(n2+key[3]);
			n2 ^= rot(n1+key[4]);
			n1 ^= rot(n2+key[5]);
			n2 ^= rot(n1+key[6]);
			n1 ^= rot(n2+key[7]);

			n2 ^= rot(n1+key[7]);
			n1 ^= rot(n2+key[6]);
			n2 ^= rot(n1+key[5]);
			n1 ^= rot(n2+key[4]);
			n2 ^= rot(n1+key[3]);
			n1 ^= rot(n2+key[2]);
			n2 ^= rot(n1+key[1]);
			n1 ^= rot(n2+key[0]);

			n2 ^= rot(n1+key[7]);
			n1 ^= rot(n2+key[6]);
			n2 ^= rot(n1+key[5]);
			n1 ^= rot(n2+key[4]);
			n2 ^= rot(n1+key[3]);
			n1 ^= rot(n2+key[2]);
			n2 ^= rot(n1+key[1]);
			n1 ^= rot(n2+key[0]);

			n2 ^= rot(n1+key[7]);
			n1 ^= rot(n2+key[6]);
			n2 ^= rot(n1+key[5]);
			n1 ^= rot(n2+key[4]);
			n2 ^= rot(n1+key[3]);
			n1 ^= rot(n2+key[2]);
			n2 ^= rot(n1+key[1]);
			n1 ^= rot(n2+key[0]);

			output[0] = n2;
			output[1] = n1;
		}
	}
}
