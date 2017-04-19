// hashfile.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

//WolfSSL for hashing
#include <wolfssl\wolfcrypt\hash.h>


//std::library
#include <cstdint>

#include <iostream>
#include <fstream>
#include <iomanip>

#include <string>

#include <filesystem>

using namespace std;
using namespace std::tr2::sys;


//Get the Hash Block Size
int GetHashBlockSize(wc_HashType hash_type)
{
	int iHashBlockSize = 0;

	switch (hash_type)
	{
	case WC_HASH_TYPE_MD5:
		iHashBlockSize = MD5_BLOCK_SIZE;
		break;
	case WC_HASH_TYPE_SHA:
		iHashBlockSize = SHA_BLOCK_SIZE;
		break;
	case WC_HASH_TYPE_SHA256:
		iHashBlockSize = SHA256_BLOCK_SIZE;
		break;
	case WC_HASH_TYPE_SHA512:
		iHashBlockSize = SHA512_BLOCK_SIZE;
		break;
	}

	return iHashBlockSize;
}

//Parse the command line
vector<string> ParseCommandLineArguments(int iargs, char* szargs[])
{
	string strBuildCommand; //use to build command line argument if a quote was used
	vector<string> vCmdLineArguments;

	for (int iArg = 1; iArg < iargs; iArg++)
	{
		//check to see if argument is potentially a long path which might include spaces in it
		if (szargs[iArg][0] == '\"')
		{
			//Add the beginning of the quote argument to the string
			strBuildCommand = string(szargs[iArg]);
			iArg++;

			//hopefully the end of the argument is indicated with another quote, if not
			// then assume everything to the end of the argument list is part of the file name
			while ((strBuildCommand.data()[strBuildCommand.length()] != '\"') && (iArg < iargs))
			{
				//add to the string
				strBuildCommand += string(szargs[iArg]);
				//increment the argument item (in the for loop as well)
				iArg++;
			}

			vCmdLineArguments.push_back(strBuildCommand);

		}
		else
		{
			//Add the argument without a quotation mark to the arguments list
			vCmdLineArguments.push_back(szargs[iArg]);
		}
	}


	return vCmdLineArguments;
}


int main(int argc, char* argv[])
{

	vector<string> vCmdLineArgs = ParseCommandLineArguments(argc, argv);

	if (vCmdLineArgs.size() == 0)
	{
		cout << "please specify the hash type desired: sha1, sha256, sha512, md5" << endl;
		cout << "  also specify the file, for long pathnames please enclose in quotes" << endl;
		cout << "  e.g hashfile sha256 \"c:\\program files\\windows mail\\msoe.dll\"" << endl;

		return -1;
	}

	path pathHashFile = vCmdLineArgs.back();
	uintmax_t uiBytesLeftInFile = 0;
	uintmax_t uiFileSize = 0;
	fstream fsHashFile;
	byte bFileBuffer[1024] = { }; //maximum input bytes is 1024

	//validate the file exists, if not then exit the program early
	if (exists(pathHashFile) == true)
	{
		//retrieve the file size
		uiFileSize = file_size(pathHashFile);

		//open the file stream
		fsHashFile.open(pathHashFile.string(), fstream::binary | fstream::in );

		//verify the file is opened and then retrieve the file contents for hashing
		if (fsHashFile.is_open() == false)
		{
			cout << "failed to open file: " << pathHashFile.c_str() << endl;
			return -1;
		}
	}
	else
	{
		//the file doesn't exist
		cout << "error the file: " << pathHashFile.c_str() << " was not found" << endl;
		return -1;
	}

	//hash vars
	wc_HashAlg hashAlg; //hash structure being used for hash generation
	byte bHashDigest[128] = { }; //hash digest is a maximum of 64 bytes
	size_t sHashDigestSize = 0; //how large is the digest intended to be
	size_t sHashBlockSize = 0; //used to determine number of bytes to read from file at a time
	wc_HashType hashType; //which block cipher is being used (is that correct terminology?)


	//determine the hash cipher desired by the command linge argument
	if (_stricmp(vCmdLineArgs[0].c_str(), "sha1") == 0)
	{
		hashType = WC_HASH_TYPE_SHA;
	}
	else if (_stricmp(vCmdLineArgs[0].c_str(), "sha256") == 0)
	{
		hashType = WC_HASH_TYPE_SHA256;
	}
	else if (_stricmp(vCmdLineArgs[0].c_str(), "sha512") == 0)
	{
		hashType = WC_HASH_TYPE_SHA512;
	}
	else if (_stricmp(vCmdLineArgs[0].c_str(), "md5") == 0)
	{
		hashType = WC_HASH_TYPE_MD5;
	}
	else
	{
		//unknown cipher was requested
		cout << "unknown cipher: " << vCmdLineArgs[0].c_str() << endl;
		goto cleanup;

	}

	//Get the Digest and Block Size
	sHashDigestSize = wc_HashGetDigestSize(hashType);
	sHashBlockSize = GetHashBlockSize(hashType);

	//Init the hash structure
	wc_HashInit(&hashAlg, hashType);

	//Set the bytes left to be read from the file
	uiBytesLeftInFile = uiFileSize;

	//Stream in the file and create a hash from the file being streamed in
	// this method is to avoid massive allocations (especially for exceedingly large files)
	// and should still run fairly fast thanks to WolfSSL or WolfCrypto
	while (uiBytesLeftInFile > 0)
	{
		//read in contents from the file
		fsHashFile.read(reinterpret_cast<char*>(bFileBuffer), min(sHashBlockSize, uiBytesLeftInFile));

		//hash the contents
		wc_HashUpdate(&hashAlg, hashType, (const byte*)bFileBuffer, static_cast<word32>(min(sHashBlockSize, uiBytesLeftInFile)));

		//subtract the bytes read from uiBytesLeftInFile
		uiBytesLeftInFile -= min(sHashBlockSize, uiBytesLeftInFile);
	}

	//Get the completed hash
	wc_HashFinal(&hashAlg, hashType, bHashDigest);

	//human readable output
	cout << vCmdLineArgs[0].c_str() << " hash of file " << pathHashFile.string().c_str() << endl;

	for (int ibyte = 0; ibyte < sHashDigestSize; ibyte++)
	{
		cout << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << int(bHashDigest[ibyte]);
	}

	cout << endl;

cleanup:

	//close the file
	if ( fsHashFile.is_open() == true )
	{
		fsHashFile.close();
	}

    return 0;
}

