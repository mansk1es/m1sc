#include <iostream>
#include <Windows.h>
#include <windowsx.h>
#include <Vfw.h>

#pragma comment(lib, "vfw32.lib")

int main()
{
    HWND hWndC = capCreateCaptureWindowA("wtfbbq", WS_CHILD,       // window style 
        0, 0, 0, 0,              // window position and dimensions
        GetDesktopWindow(),
        0);

    auto fOK = capDriverConnect(hWndC, 0);
    LPBITMAPINFO lpbi;
    DWORD dwSize;

    dwSize = capGetVideoFormatSize(hWndC);
    lpbi = (LPBITMAPINFO)GlobalAllocPtr(GHND, dwSize);
    capGetVideoFormat(hWndC, lpbi, dwSize);
    
    CAPTUREPARMS parms;

    capCaptureGetSetup(hWndC, &parms, sizeof(CAPTUREPARMS));
    parms.fLimitEnabled = TRUE;
    parms.wTimeLimit = 9; // capture for 9 secs, change it to an argument for easier config I guess
    capCaptureSetSetup(hWndC, &parms, sizeof(CAPTUREPARMS));


    // save avi file
    char szCaptureFile[] = "3";

    capFileSetCaptureFile(hWndC, szCaptureFile);
    capFileAlloc(hWndC, (1024L * 1024L * 5));

    char szNewName[] = "4";
    // Set up the capture operation.
    // Capture
    capCaptureSequence(hWndC);

    if (!capFileSaveAs(hWndC, szNewName)) {
        printf("save failed: %d\n", GetLastError());
        return -1;
    }

    if (!DeleteFile(L"3")) {
        printf("error deleting: %d\n", GetLastError());
    }
  
    MoveFile(L"4", L"video.avi");
    
    //printf("hWndC: %d\n", hWndC);
  
    capDriverDisconnect(hWndC);
    
    return 0;

}
