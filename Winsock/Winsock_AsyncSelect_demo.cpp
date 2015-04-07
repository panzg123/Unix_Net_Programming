// Winsock_AsyncSelect_demo.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "Winsock_AsyncSelect_demo.h"
#include <WinSock2.h>



#define MAX_LOADSTRING 100
#define PORT 8000
#define WM_SOCKET WM_USER+0
#define MSGSIZE   1024  

#pragma comment(lib, "ws2_32.lib")

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

 	// TODO: Place code here.
	MSG msg;
	HACCEL hAccelTable;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_WINSOCK_ASYNCSELECT_DEMO, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_WINSOCK_ASYNCSELECT_DEMO));

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage are only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_WINSOCK_ASYNCSELECT_DEMO));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_WINSOCK_ASYNCSELECT_DEMO);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // Store instance handle in our global variable

   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;


	//winsock asyncSelect code
	WSADATA  wsd;  
	static SOCKET sListen;  
	SOCKET   sClient;  
	SOCKADDR_IN   local, client;  
	int ret, iAddrSize = sizeof(client);  
	char  szMessage[MSGSIZE];  

	switch (message)
	{
	case WM_CREATE:

		// Initialize Windows Socket library  
		WSAStartup(0x0202, &wsd);  
		// Create listening socket  
		sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  
		// Bind  
		local.sin_addr.S_un.S_addr = htonl(INADDR_ANY);  
		local.sin_family = AF_INET;  
		local.sin_port = htons(PORT);  
		bind(sListen, (struct sockaddr *)&local, sizeof(local));  
		// Listen  
		listen(sListen, 3);  
		// Associate listening socket with FD_ACCEPT event  
		WSAAsyncSelect(sListen, hWnd, WM_SOCKET, FD_ACCEPT);  

		break;
	case WM_SOCKET:  
		if (WSAGETSELECTERROR(lParam))  
		{  
			closesocket(wParam);  
			break;  
		}  
		switch (WSAGETSELECTEVENT(lParam))  
		{  
		case FD_ACCEPT:  
			// Accept a connection from client  
			sClient = accept(wParam, (struct sockaddr *)&client, &iAddrSize);  
			// Associate client socket with FD_READ and FD_CLOSE event  
			WSAAsyncSelect(sClient, hWnd, WM_SOCKET, FD_READ | FD_CLOSE);  
			break;  
		case FD_READ:  
			ret = recv(wParam, szMessage, MSGSIZE, 0);  
			if (ret == 0 || ret == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)  
			{  
				closesocket(wParam);  
			}  
			else  
			{  
				szMessage[ret] = '\0';  
				send(wParam, szMessage, strlen(szMessage), 0);  
			}  
			break;  
		case FD_CLOSE:  
			closesocket(wParam);  
			break;  
		}  
		return 0;  
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		// TODO: Add any drawing code here...
		EndPaint(hWnd, &ps);
		break;
	case WM_DESTROY:
		closesocket(sListen);  
		WSACleanup();  
		PostQuitMessage(0);  
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
