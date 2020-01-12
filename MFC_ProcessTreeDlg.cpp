
// MFC_ProcessTreeDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "MFC_ProcessTree.h"
#include "MFC_ProcessTreeDlg.h"
#include "afxdialogex.h"
//用于遍历进程的需要的头文件
#include<iostream>
#include <string>
#include<windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Strsafe.h>
#include "PEFunction.h"
#include <winsvc.h> 
#include <Winsvc.h>
#include "md5.h"
#include <PowrProf.h>
#include<sstream>
#include"MD5forFile.h"
#include<vector>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//用于将char字符串转为wchar_字符串
#define  CHAR_TO_WCHAR(lpChar, lpW_Char) MultiByteToWideChar(CP_ACP, NULL, lpChar, -1, lpW_Char, _countof(lpW_Char));
#define  WCHAR_TO_CHAR(lpW_Char, lpChar) WideCharToMultiByte(CP_ACP, NULL, lpW_Char, -1, lpChar, _countof(lpChar), NULL, FALSE);

//需要在cpp中定义全局变量
//用于从回调函数中接收窗口名
TCHAR *WinName[200] = { NULL };
//用于计数接收了多少个窗口名
int NameNum = 0;

bool _trace(TCHAR *format, ...) //变参函数
{
	TCHAR buffer[1000];
	va_list argptr;
	va_start(argptr, format);
	//将格式化信息写入指定的缓冲区
	wvsprintf(buffer, format, argptr);
	va_end(argptr);
	//将缓冲区信息输出
	OutputDebugString(buffer);
	return true;
}


//提升进程访问权限  
bool enableDebugPriv()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	//获得当前进程的令牌
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return false;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		CloseHandle(hToken);
		return false;
	}
	return true;
}


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCProcessTreeDlg 对话框
CMFCProcessTreeDlg::CMFCProcessTreeDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFC_PROCESSTREE_DIALOG, pParent)
	, m_ChoseButton(FALSE)
	, ServiceChose(FALSE)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCProcessTreeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST3, m_list);
	DDX_Radio(pDX, IDC_RADIO1, m_ChoseButton);
	DDX_Control(pDX, IDC_RADIO12, ServiceChange);
	DDX_Radio(pDX, IDC_RADIO12, ServiceChose);
}

BEGIN_MESSAGE_MAP(CMFCProcessTreeDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCProcessTreeDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCProcessTreeDlg::OnBnClickedButton2)
ON_BN_CLICKED(IDC_BUTTON3, &CMFCProcessTreeDlg::RecycleBinClean)
ON_BN_CLICKED(IDC_BUTTON4, &CMFCProcessTreeDlg::DeleteSysGarbage)
ON_BN_CLICKED(IDC_BUTTON5, &CMFCProcessTreeDlg::PEFileParser)
ON_BN_CLICKED(IDC_BUTTON6, &CMFCProcessTreeDlg::ChangeServicesState)
ON_BN_CLICKED(IDC_BUTTON8, &CMFCProcessTreeDlg::MD5KillVirus)
ON_BN_CLICKED(IDC_BUTTON9, &CMFCProcessTreeDlg::ShutDown)
ON_BN_CLICKED(IDC_BUTTON10, &CMFCProcessTreeDlg::ReBoot)
ON_BN_CLICKED(IDC_BUTTON11, &CMFCProcessTreeDlg::LogOff)
ON_BN_CLICKED(IDC_BUTTON12, &CMFCProcessTreeDlg::Dormancy)
ON_BN_CLICKED(IDC_BUTTON13, &CMFCProcessTreeDlg::Sleep)
ON_BN_CLICKED(IDC_BUTTON14, &CMFCProcessTreeDlg::LockWindows)

ON_BN_CLICKED(IDC_BUTTON7, &CMFCProcessTreeDlg::AllRoadVirusKill)
ON_BN_CLICKED(IDC_BUTTON15, &CMFCProcessTreeDlg::BlackList)
ON_BN_CLICKED(IDC_BUTTON16, &CMFCProcessTreeDlg::CloudVirusKill)
ON_BN_CLICKED(IDC_BUTTON17, &CMFCProcessTreeDlg::KillVirusAccordingToCloud)
ON_BN_CLICKED(IDC_BUTTON18, &CMFCProcessTreeDlg::ProcessProtect)
END_MESSAGE_MAP()


// CMFCProcessTreeDlg 消息处理程序

BOOL CMFCProcessTreeDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	m_list.InsertColumn(0, L" ", 0, 80);
	m_list.InsertColumn(1, L" ", 0, 90);
	m_list.InsertColumn(2, L" ", 0, 90);
	m_list.InsertColumn(3, L" ", 0, 90);
	m_list.InsertColumn(4, L" ", 0, 90);
	m_list.InsertColumn(5, L" ", 0, 90);
	
	//设置list控件的网格线
	DWORD NewStyle = LVS_EX_GRIDLINES;
	m_list.SetExtendedStyle(NewStyle);

	//enableDebugPriv();
	//注册全局热键  Alt+A
	::RegisterHotKey(this->GetSafeHwnd(),0Xa001,
		MOD_ALT,
		'A');

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMFCProcessTreeDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCProcessTreeDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMFCProcessTreeDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



//获取按键，根据单选框的不同，获取不同的信息
void CMFCProcessTreeDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
		//设置可以打印中文
	m_list.DeleteAllItems();
	//UpdateData(FALSE);

	UpdateData(TRUE);

	switch (m_ChoseButton)
	{
	case 0:
		//遍历进程及其模块
		GetProcessAndModule();
		break;
	case 1:
		//遍历进程及其线程
		GetProcessAndThread();
		break;
	case 2:
		//获得进程堆信息
		GetHeap();
		break;
	case 3://输出窗口信息
	{
		m_list.InsertItem(0, L"窗口名");

		//EnumWindows函数会遍历当前界面上所有窗口，并以此调用对应回调函数
		EnumWindows(&EnumWindowsProc, NULL);//这里因为EnumWindows是api所以其回调函数不能为类的成员函数，此时回调函数无法直接使用m_list

		for (int i = 0; i < NameNum; i++)
		{
			_trace(L"%s\n", WinName[i]);
			m_list.InsertItem(1, WinName[i]);

			//delete[]WinName[i];这里似乎不需要使用delete[]，WinName全局变量是分配在栈上的而非堆上的
			//将指针置为空
			WinName[i] = NULL;
		}
		//将全局变量n置为0
		NameNum = 0;
	}
	break;
	case 4:
	{
		m_list.InsertItem(0, L"文件夹");
		m_list.SetItemText(0, 1, L"文件名");
		m_list.SetItemText(0, 2, L"创建时间");
		m_list.SetItemText(0, 3, L"最后一次修改时间");
		m_list.SetItemText(0, 4, L"文件大小（kb）");
		m_list.SetItemText(0, 5, L"文件MD5");

		//为了方便递归遍历文件夹，仅仅遍历某个具体指定的文件接
		int size = sizeof(L"D:\\学习\\财务管理\\*");
		GetFile(L"D:\\学习\\财务管理\\*", size);
		break;
	}
	case 5:
		GetMem();
		break;
	case 6:
		CpuTime();
		break;
	case 7://系统垃圾
	{
		m_list.InsertItem(0, L"文件夹");
		m_list.SetItemText(0, 1, L"文件名");

		int size = sizeof(L"C:\\Windows\\Temp\\*");
		GetFile2(L"C:\\Windows\\Temp\\*", size);

		int size1 = sizeof(L"C:\\Users\\李嘉柏\\AppData\\Local\\Temp\\*");
		GetFile2(L"C:\\Users\\李嘉柏\\AppData\\Local\\Temp\\*", size1);

		int size2 = sizeof(L"C:\\Users\\李嘉柏\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportQueue\\*");
		GetFile2(L"C:\\Users\\李嘉柏\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportQueue\\*", size2);

		break;
	}

	case 8://浏览器垃圾
	{
		//C:\Users\李嘉柏\AppData\Local\Mozilla\Firefox\Profiles\mko98c82.default\cache2\entries   火狐浏览器网站缓存
		m_list.InsertItem(0, L"");
		m_list.SetItemText(0, 1, L"");
		m_list.InsertItem(1, L"浏览器垃圾");
		m_list.SetItemText(1, 1, L"浏览器网页缓存");
		int size3 = sizeof(L"C:\\Users\\李嘉柏\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\mko98c82.default\\cache2\\entries\\*");
		GetFile2(L"C:\\Users\\李嘉柏\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\mko98c82.default\\cache2\\entries\\*", size3);
		break;
	}
	case 9://VS垃圾
	{
		m_list.InsertItem(0, L"");
		m_list.SetItemText(0, 1, L"");
		m_list.InsertItem(1, L"VS路径");
		m_list.SetItemText(1, 1, L"VS调试中间结果");
		//int size4 = sizeof(L"E:\\c源码\\贪吃蛇\\*");
		//GetVSGarbage(L"E:\\c源码\\贪吃蛇\\*", size4);
		int size4 = sizeof(L"E:\\c源码\\坦克大战 (升级版)\\*");
		GetVSGarbage(L"E:\\c源码\\坦克大战 (升级版)\\*", size4);
		break;
	}
	case 10://遍历服务，需要以管理员权限运行
	{
		ErgodicServices();
		break;
	}

	}
	UpdateData(FALSE);
}


//获取模块信息（弃用）
void CMFCProcessTreeDlg::GetModule(DWORD dwPid)
{
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,//创建模块快照
		dwPid);//进程的pid
	MODULEENTRY32 moduleInfo = { sizeof(MODULEENTRY32) };

	if (Module32First(hSnap, &moduleInfo))
	{
		do {
			TCHAR AddrThread[100] = { 0 };
			TCHAR SizeThread[100] = { 0 };
			TCHAR NameThread[100] = { 0 };

			//将模块名称转为字符串
			_stprintf_s(NameThread, 100, _T("%s"), moduleInfo.szModule);
			//将模块地址转为字符串
			_stprintf_s(AddrThread, 100, _T("%d"), moduleInfo.modBaseAddr);
			//将模块内存大小转为字符串
			_stprintf_s(SizeThread, 100, _T("%d"), moduleInfo.modBaseSize);

			UpdateData(TRUE);

			//打印两个空格用于占行
			m_list.InsertItem(2, L" ");
			m_list.SetItemText(2, 1, L" ");

			m_list.SetItemText(2, 2, (TCHAR*)NameThread);//输出模块名
			m_list.SetItemText(2, 3, (TCHAR*)AddrThread);//输出模块地址
			m_list.SetItemText(2, 4, (TCHAR*)SizeThread);//输出模块大小

			UpdateData(FALSE);

			//moduleInfo.modBaseAddr;//模块在内存中的加载基址
			//moduleInfo.modBaseSize;//模块占据内存大小
			//moduleInfo.szModule;//模块名称	
		} while (Module32Next(hSnap, &moduleInfo));
	//OpenProcess
	}
	CloseHandle(hSnap);
}

//获取32位和64位模块（启用）
void CMFCProcessTreeDlg::GetModule32and64(DWORD dwPid)
{
	//获得指定进程的句柄
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	
	//确定特定进程需要多少内存储存信息
	DWORD dwBufferSize = 0;
	::EnumProcessModulesEx(hProcess, NULL, 0,&dwBufferSize, LIST_MODULES_ALL);
	
	//申请空间存储模块句柄数组
	HMODULE* pModuleHandleArr = (HMODULE*)new char[dwBufferSize];
	
	//获得特定进程所有模块
	::EnumProcessModulesEx(hProcess, pModuleHandleArr, dwBufferSize, &dwBufferSize, LIST_MODULES_ALL);
	
	for (int i = 0; i < dwBufferSize / sizeof(HMODULE); i++)
	{
		//定义数组接收模块名
		TCHAR szModuleName[MAX_PATH] = { 0 };

		//定义结构体接收模块信息
		MODULEINFO stcModuleInfo = { 0 };
		
		//获取输出模块的信息
		GetModuleInformation(hProcess, pModuleHandleArr[i], &stcModuleInfo,sizeof(MODULEINFO));
		
		//获取模块文件名，包括路径
		GetModuleFileNameEx(hProcess, pModuleHandleArr[i], szModuleName, MAX_PATH);
		
			TCHAR AddrThread[100] = { 0 };
			TCHAR SizeThread[100] = { 0 };

			//将模块地址转为字符串
			_stprintf_s(AddrThread, 100, _T("%x"), stcModuleInfo.lpBaseOfDll);
			//将模块内存大小转为字符串
			_stprintf_s(SizeThread, 100, _T("%d"), stcModuleInfo.SizeOfImage);

			UpdateData(TRUE);

			//打印两个空格用于占行
			m_list.InsertItem(2, L" ");
			m_list.SetItemText(2, 1, L" ");

			m_list.SetItemText(2, 2, (TCHAR*)szModuleName);//输出模块名
			m_list.SetItemText(2, 3, (TCHAR*)AddrThread);//输出模块地址
			m_list.SetItemText(2, 4, (TCHAR*)SizeThread);//输出模块大小

			UpdateData(FALSE);
	}

	delete[] pModuleHandleArr;
}

//获取当前进程和进程模块
void CMFCProcessTreeDlg::GetProcessAndModule() {
	//允许显示中文
	setlocale(LC_ALL, "chs");
	//创建一个进程快照
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

	//该结构体用于接收所有进程信息，该结构体在调用Process32First需要将其字段dwSize 赋值为当前结构体大小
	//PROCESSENTRY32 procInfo = {sizeof(PROCESSENTRY32)};
	PROCESSENTRY32 procInfo = { 0 };
	procInfo.dwSize = sizeof(PROCESSENTRY32);
	
	//如果有快照信息可以接收
	if (Process32First(hSnap, &procInfo))
	{

		m_list.InsertItem(0, L"进程id");
		m_list.SetItemText(0, 1, L"进程名称");
		m_list.SetItemText(0, 2, L"模块名");//输出模块名
		m_list.SetItemText(0, 3, L"模块地址");//输出模块地址
		m_list.SetItemText(0, 4, L"模块大小");//输出模块大小
		
		do {
			//使用通用版字符串储存进程名称和进程id
			TCHAR IdString[100] = { 0 };
			TCHAR NameString[100] = { 0 };
			//将进程id转为字符串
			_stprintf_s(IdString, 100, _T("%d"), procInfo.th32ProcessID);
			//将进程名称转为字符串
			_stprintf_s(NameString, 100, _T("%s"), procInfo.szExeFile);

			UpdateData(TRUE);
			//输出进程id信息
			m_list.InsertItem(1, (TCHAR*)IdString);
			//输出进程名称
			m_list.SetItemText(1, 1, (TCHAR*)NameString);
			//用于占行
			m_list.SetItemText(1, 2, L" ");
			m_list.SetItemText(1, 3, L" ");
			m_list.SetItemText(1, 4, L" ");

			//查询进程对应的模块
			GetModule32and64(procInfo.th32ProcessID);

			//获取进程对应的线程
			//GetThread(procInfo.th32ProcessID);
			UpdateData(FALSE);

		} while (Process32Next(hSnap, &procInfo));//获取下一个进程的信息		
	}
	CloseHandle(hSnap);
}


//获取指定进程的线程
void CMFCProcessTreeDlg::GetThread(DWORD dwPid) {

	HANDLE hSnap = INVALID_HANDLE_VALUE;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,//创建线程快照
		0);

	//THREADENTRY32 ThreadInfo = {sizeof(THREADENTRY32)};
	THREADENTRY32 ThreadInfo = {0};
	ThreadInfo.dwSize = sizeof(THREADENTRY32);
	
	if (Thread32First(hSnap, &ThreadInfo))
	{
		do {
			if (ThreadInfo.th32OwnerProcessID == dwPid)//当线程的进程id匹配到的时候
			{
				//用于储存线程相关信息
				TCHAR PriThread[100] = { 0 };
				TCHAR SizeThread[100] = { 0 };
				TCHAR IdThread[100] = { 0 };

				//线程id
				_stprintf_s(IdThread, 100, _T("%d"), ThreadInfo.th32ThreadID);//这里串拼接的格式标识符应该是需要被转换为字符串的变量的数据类型
				//线程优先级
				_stprintf_s(PriThread, 100, _T("%d"), ThreadInfo.tpBasePri);
				//线程父进程id
				_stprintf_s(SizeThread, 100, _T("%d"), ThreadInfo.th32OwnerProcessID);

				UpdateData(TRUE);

				//打印两个空格用于占行
				m_list.InsertItem(2, L" ");
				m_list.SetItemText(2, 1, L" ");

				m_list.SetItemText(2, 2, (TCHAR*)IdThread);//输出线程id
				m_list.SetItemText(2, 3, (TCHAR*)PriThread);//输出线程优先级
				m_list.SetItemText(2, 4, (TCHAR*)SizeThread);//输出线程父id

				UpdateData(FALSE);

				//ThreadInfo.tpBasePri  线程优先级 
				//ThreadInfo.th32ThreadID  线程id
				//ThreadInfo.dwSize  线程字节数
			}
		} while (Thread32Next(hSnap, &ThreadInfo));
	}
	CloseHandle(hSnap);
}

//获取进程及其线程
void CMFCProcessTreeDlg::GetProcessAndThread() {
	setlocale(LC_ALL, "chs");
	//创建一个进程快照
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	//该结构体用于接收所有进程信息，该结构体在调用Process32First需要将其字段dwSize 赋值为当前结构体大小
	//PROCESSENTRY32 procInfo = {sizeof(PROCESSENTRY32)};
	PROCESSENTRY32 procInfo = { 0 };
	procInfo.dwSize = sizeof(PROCESSENTRY32);

	//如果有快照信息可以接收
	if (Process32First(hSnap, &procInfo))
	{
		m_list.InsertItem(0, L"进程id");
		m_list.SetItemText(0, 1, L"进程名称");
		m_list.SetItemText(0, 2, L"线程id");
		m_list.SetItemText(0, 3, L"线程优先级");
		m_list.SetItemText(0, 4, L"线程父进程id");
		do {
			//使用通用版字符串将储存进程名称和进程id
			TCHAR IdString[100] = { 0 };
			TCHAR NameString[100] = { 0 };
			
			//将进程id转为字符串
			_stprintf_s(IdString, 100, _T("%d"), procInfo.th32ProcessID);
			//将进程名称转为字符串
			_stprintf_s(NameString, 100, _T("%s"), procInfo.szExeFile);

			UpdateData(TRUE);

			//输出进程id信息
			m_list.InsertItem(1, (TCHAR*)IdString);
			//输出进程名称
			m_list.SetItemText(1, 1, (TCHAR*)NameString);
			//用于占行
			m_list.SetItemText(1, 2, L" ");
			m_list.SetItemText(1, 3, L" ");
			m_list.SetItemText(1, 4, L" ");

			//查询进程对应的模块
			//GetModule(procInfo.th32ProcessID);

			//获取进程对应的线程
			GetThread(procInfo.th32ProcessID);

			UpdateData(FALSE);

		} while (Process32Next(hSnap, &procInfo));//获取下一个进程的信息		
	}
	CloseHandle(hSnap);
}

//获取进程堆信息
void CMFCProcessTreeDlg::GetHeap(){
	//设置本地信息，以便可以打印中文
	setlocale(LC_ALL, "chs");

	// 1. 创建一个进程快照
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,/*快照的类型: 进程,进程的模块,线程,进程的堆*/
		0/*进程ID,遍历进程时不需要用到.传0即可*/);
	// 2. 使用一组API提取出进程快照的内容
	PROCESSENTRY32 procInfo = { sizeof(PROCESSENTRY32) };//用于从快照中接收进程信息

	m_list.InsertItem(0, L"进程id");
	m_list.SetItemText(0, 1, L"进程堆id");
	m_list.SetItemText(0, 2, L"进程堆所属进程id");

	if (Process32First(hSnap, &procInfo))//接收第一个进程信息
	{
		do
		{
			//用于保存进程id
			TCHAR IdProcess[100] = { 0 };
			//将进程id转为字符串
			_stprintf_s(IdProcess, 100, _T("%d"), procInfo.th32ProcessID);

			m_list.InsertItem(1, (TCHAR*)IdProcess);
			m_list.SetItemText(1, 1, L" ");
			m_list.SetItemText(1, 2, L" ");

			// 接着获取这个对应进程的所有进程堆
			////////////////////////////////////////////////////////////
			//创建进程堆的快照
			HANDLE hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, procInfo.th32ProcessID);
			
			HEAPLIST32 hl;
			hl.dwSize = sizeof(HEAPLIST32);

			if (Heap32ListFirst(hHeapSnap, &hl))
			{
				do
				{				
					TCHAR IdHeap[100] = { 0 };
					TCHAR IdProcess[100] = { 0 };
					
					//将进程id转为字符串
					_stprintf_s(IdHeap, 100, _T("%u"), hl.th32HeapID);
					_stprintf_s(IdProcess, 100, _T("%u"), hl.th32ProcessID);

					m_list.InsertItem(2,L" ");
					m_list.SetItemText(2,1,(TCHAR*)IdHeap);
					m_list.SetItemText(2,2, (TCHAR*)IdProcess);

				} while (Heap32ListNext(hHeapSnap, &hl));
			}
			CloseHandle(hHeapSnap);
		} while (Process32Next(hSnap, &procInfo));
	}
	//关闭快照句柄
	CloseHandle(hSnap);
}

//枚举窗口信息
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {

	setlocale(LC_ALL, "chs");//注意系统信息中需要输出中文的敌方需要使用该函数
	
	//在回调函数中申请内存，用于保存接收到的窗口名，将堆空间的地址保存在全局指针数组中，
	//使得可以在回调函数外步得到窗口名，堆空间的销毁也发生在回调函数外部，所以需要计数
	//n堆读取的窗口名数量进行记录
	TCHAR* pbuff= new TCHAR[200]();

	GetWindowText(hWnd,pbuff,200);//这里这一需要使用全局的函数，不能使用对话框类中定义的函数，后者比前者少一个参数
	
	if (::IsWindowVisible(hWnd) == TRUE && wcslen(pbuff) != 0)
	{
		//将堆空间指针保存起来
		WinName[NameNum] = pbuff;
		//窗口计数+1
		NameNum++;
	}
	return TRUE;//注意这里只有返回true才能遍历所有的窗口，否则会直接返回
}

//获取文件信息，后期为了遍历整个文件系统，需要使用递归遍历
//遍历文件，并输出文件相关信息（目前在用）
void CMFCProcessTreeDlg::GetFile(WCHAR*Path,int SizeOfFilePath) {

	setlocale(LC_ALL, "chs");//注意系统信息中需要输出中文的敌方需要使用该函数
	HANDLE hFind;
	WIN32_FIND_DATA fData;

	//将参数中的路径保存在数组中，使用该数组作为路径进行文件遍历
	WCHAR FilePath[MAX_PATH] = {0};
	memcpy((void*)FilePath, Path, SizeOfFilePath);

	hFind = FindFirstFile(FilePath, &fData);
	if (hFind == (HANDLE)-1) return;
	do {
		if (!wcscmp(fData.cFileName, L".") || !wcscmp(fData.cFileName, L".."))//避免遍历隐藏的本目录路径以及父目录路径
			continue;
		//如果当前文件是文件夹，则需要递归遍历该文件夹中的文件
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WCHAR FilePathNext[MAX_PATH] = { 0 };
			
			StringCchPrintf(FilePathNext, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			FilePathNext[SizeOfFilePath / 2-2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(FilePathNext, MAX_PATH, fData.cFileName);//将遍历到文件夹名称追加上去，形成新的路径
			StringCchCat(FilePathNext, MAX_PATH,L"\\*");//将遍历到文件名追加上去，形成新的路径
			
			int size = wcslen(FilePathNext)+1;
			
			UpdateData(TRUE);
			m_list.InsertItem(1, (TCHAR*)FilePathNext);
			m_list.SetItemText(1, 1, L" ");
			UpdateData(FALSE);

			//递归遍历下一个文件夹
			GetFile(FilePathNext, size*2);
		}
		else
		{
			//拼接文件全路径
			WCHAR MD5FilePath[MAX_PATH] = { 0 };
			StringCchPrintf(MD5FilePath, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			MD5FilePath[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(MD5FilePath, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			
			//将路径转化为char类型
			char md5filepath[MAX_PATH] = { 0 };
			WCHAR_TO_CHAR(MD5FilePath, md5filepath);


			UpdateData(TRUE);
			m_list.InsertItem(2, L" ");
			m_list.SetItemText(2, 1, (TCHAR*)fData.cFileName);//文件名

			//输出文件创建时间		
			SYSTEMTIME st = { 0 };
			char buf[64] = { 0 };
			FileTimeToSystemTime(&fData.ftCreationTime, &st);
			sprintf(buf, "%4d-%02d-%02d %02d:%02d:%2d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);	
			USES_CONVERSION;		
			wchar_t* CreateTimeOfFile = A2W(buf);	
			m_list.SetItemText(2, 2, CreateTimeOfFile);

			//输出文件修改时间
			SYSTEMTIME st2 = { 0 };
			char buf2[64] = { 0 };
			FileTimeToSystemTime(&fData.ftLastWriteTime, &st2);
			sprintf(buf2, "%4d-%02d-%02d %02d:%02d:%2d", st2.wYear, st2.wMonth, st2.wDay, st2.wHour, st2.wMinute, st2.wSecond);
			//USES_CONVERSION;
			wchar_t* ChangeTimeOfFile = A2W(buf2);
			m_list.SetItemText(2, 3, ChangeTimeOfFile);

			//输出文件md5值
			TCHAR SizeOfFileStr[100] = { 0 };
			DWORD SizeOfFile = (fData.nFileSizeHigh * (MAXDWORD + 1)) + fData.nFileSizeLow;
			//将文件总字节数转为字符串
			_stprintf_s(SizeOfFileStr, 100, _T("%d"), SizeOfFile/1024);
			m_list.SetItemText(2, 4, SizeOfFileStr);
	
			//输出文件md5
			MD52 MD52;
			char*md5offile = MD52.digestFile(md5filepath);
			//USES_CONVERSION;
			wchar_t* MD5ofFile = A2W(md5offile);
			m_list.SetItemText(2, 5, MD5ofFile);
				
			UpdateData(FALSE);
		
		}
	} while (FindNextFile(hFind, &fData));
}

//递归遍历文件系统，只能用于遍历文件名称，不能输出文件属性相关信息，目前弃用
void CMFCProcessTreeDlg::GetFile2(WCHAR*Path, int SizeOfFilePath) {//暂时只能遍历d盘

	setlocale(LC_ALL, "chs");//注意系统信息中需要输出中文的敌方需要使用该函数
	HANDLE hFind;
	WIN32_FIND_DATA fData;

	//将参数中的路径保存在数组中，使用该数组作为路径进行文件遍历
	WCHAR FilePath[MAX_PATH] = { 0 };
	memcpy((void*)FilePath, Path, SizeOfFilePath);

	hFind = FindFirstFile(FilePath, &fData);
	if (hFind == (HANDLE)-1) return;

	do {
		if (!wcscmp(fData.cFileName, L".") || !wcscmp(fData.cFileName, L".."))//避免遍历隐藏的本目录路径以及父目录路径
			continue;
		//如果当前文件是文件夹，则需要递归遍历该文件夹中的文件
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WCHAR FilePathNext[MAX_PATH] = { 0 };

			StringCchPrintf(FilePathNext, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			FilePathNext[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(FilePathNext, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			StringCchCat(FilePathNext, MAX_PATH, L"\\*");//将遍历到文件名追加上去，形成新的路径

			int size = wcslen(FilePathNext) + 1;

			UpdateData(TRUE);
			m_list.InsertItem(1, (TCHAR*)FilePathNext);
			m_list.SetItemText(1, 1, L" ");
			UpdateData(FALSE);

			//递归遍历下一个文件夹
			GetFile2(FilePathNext, size * 2);
		}
		else
		{
			//拼接文件全路径
			WCHAR MD5FilePath[MAX_PATH] = { 0 };
			StringCchPrintf(MD5FilePath, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			MD5FilePath[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(MD5FilePath, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径

			//将路径转化为char类型
			char md5filepath[MAX_PATH] = { 0 };
			WCHAR_TO_CHAR(MD5FilePath, md5filepath);


			UpdateData(TRUE);
			m_list.InsertItem(2, L" ");
			m_list.SetItemText(2, 1, (TCHAR*)fData.cFileName);//文件
		}
	} while (FindNextFile(hFind, &fData));
}

//获得内存信息
void CMFCProcessTreeDlg::GetMem() {

	MEMORYSTATUS memStatus;
	GlobalMemoryStatus(&memStatus);//用于获取内存相关信息

	//memStatus.dwMemoryLoad;//内存占用率
	//memStatus.dwTotalPhys - memStatus.dwAvailPhys;

	m_list.InsertItem(0, L"内存占用率(%)");
	m_list.SetItemText(0, 1, L"已用物理内存大小(GB)");

	TCHAR PMem[32] = { 0 };
	TCHAR SizeMem[32] = { 0 };
	//内存占用率
	_stprintf_s(PMem, 32, _T("%d"), memStatus.dwMemoryLoad);

	//已用物理内存大小
	_stprintf_s(SizeMem, 32, _T("%d"), (memStatus.dwTotalPhys - memStatus.dwAvailPhys) / (1024 * 1024 * 1024));

	UpdateData(TRUE);
	m_list.InsertItem(1, (TCHAR*)PMem);
	m_list.SetItemText(1, 1, (TCHAR*)SizeMem);
	UpdateData(FALSE);
}

//获得cpu时间信息
void CMFCProcessTreeDlg::CpuTime() {

	//获得空闲时间、内核时间、用户时间
	FILETIME idleTime, kernelTime, userTime;
	GetSystemTimes(&idleTime, &kernelTime, &userTime);
	//等待1000毫秒
	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	WaitForSingleObject(hEvent, 1000);

	FILETIME preidleTime, prekernelTime, preuserTime;
	GetSystemTimes(&preidleTime, &prekernelTime, &preuserTime);

	double idleTimeCount = (double)(idleTime.dwHighDateTime*4.294967296E9) + (double)(idleTime.dwLowDateTime);
	double kernelTimeCount = (double)(kernelTime.dwHighDateTime*4.294967296E9) + (double)(kernelTime.dwLowDateTime);
	double userTimeCount = (double)(userTime.dwHighDateTime*4.294967296E9) + (double)(userTime.dwLowDateTime);
	double preidleTimeCount = (double)(preidleTime.dwHighDateTime*4.294967296E9) + (double)(preidleTime.dwLowDateTime);
	double prekernelTimeCount = (double)(prekernelTime.dwHighDateTime*4.294967296E9) + (double)(prekernelTime.dwLowDateTime);
	double preuserTimeCount = (double)(preuserTime.dwHighDateTime*4.294967296E9) + (double)(preuserTime.dwLowDateTime);

	//计算cpu使用率
	double CPUpercent = (double)(100.0 - (preidleTimeCount - idleTimeCount) /
		(prekernelTimeCount - kernelTimeCount + preuserTimeCount - userTimeCount)*100.0);

	m_list.InsertItem(0, L"CPU使用率(%)");

	//将使用率转成ascii字符串	
	//这里无法使用_stprintf_s(PCPU, 5, (L"%f"), CPUpercent);直接将数字转换为unicode字符串，
	//所以先转成ASCII字符串，再转成unicode
	char PCPU[MAX_PATH] = { 0 };
	sprintf_s(PCPU, MAX_PATH, "%f", CPUpercent);

	//将ascii字符串转为unicode字符串
	wchar_t WPCPU[MAX_PATH] = { 0 };
	CHAR_TO_WCHAR(PCPU, WPCPU);

	//更新到listctrl中
	UpdateData(TRUE);
	m_list.InsertItem(1, WPCPU);
	UpdateData(FALSE);
}

//获取VS垃圾信息
void CMFCProcessTreeDlg::GetVSGarbage(WCHAR*Path, int SizeOfFilePath) {//暂时只能遍历d盘

	setlocale(LC_ALL, "chs");//注意系统信息中需要输出中文的敌方需要使用该函数
	HANDLE hFind;
	WIN32_FIND_DATA fData;

	//将参数中的路径保存在数组中，使用该数组作为路径进行文件遍历
	WCHAR FilePath[MAX_PATH] = { 0 };
	memcpy((void*)FilePath, Path, SizeOfFilePath);

	hFind = FindFirstFile(FilePath, &fData);
	
	if (hFind == (HANDLE)-1) return;

	do {
		if (!wcscmp(fData.cFileName, L".") || !wcscmp(fData.cFileName, L".."))//避免遍历隐藏的本目录路径以及父目录路径
			continue;
		//如果当前文件是文件夹，则需要递归遍历该文件夹中的文件
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WCHAR FilePathNext[MAX_PATH] = { 0 };

			StringCchPrintf(FilePathNext, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			FilePathNext[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(FilePathNext, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			StringCchCat(FilePathNext, MAX_PATH, L"\\*");//将遍历到文件名追加上去，形成新的路径

			int size = wcslen(FilePathNext) + 1;

			//UpdateData(TRUE);
			//m_list.InsertItem(1, (TCHAR*)FilePathNext);
			//m_list.SetItemText(1, 1, L" ");
			//UpdateData(FALSE);

			//递归遍历下一个文件夹
			GetVSGarbage(FilePathNext, size * 2);
		}
		else
		{
			//获取当前文件的全路径
			WCHAR VSFilePath[MAX_PATH] = { 0 };
			StringCchPrintf(VSFilePath, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			VSFilePath[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(VSFilePath, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			//获得当前文件的后缀名
			LPWSTR FileSuffix = PathFindExtension(VSFilePath);
			//比较后缀名
			if (!lstrcmp(FileSuffix, L".tlog") ||
				!lstrcmp(FileSuffix, L".obj") ||
				!lstrcmp(FileSuffix, L".log") ||
				!lstrcmp(FileSuffix, L".pch") ||
				!lstrcmp(FileSuffix, L".ilk") ||
				!lstrcmp(FileSuffix, L".pdb") 
				)
			{
				UpdateData(TRUE);
				m_list.InsertItem(2, (TCHAR*)VSFilePath);
				m_list.SetItemText(2, 1, (TCHAR*)fData.cFileName);
				UpdateData(FALSE);
			}
		}
	} while (FindNextFile(hFind, &fData));
}

//删除vs垃圾文件
void CMFCProcessTreeDlg::DeleteVSGarbage(WCHAR*Path, int SizeOfFilePath) {//暂时只能遍历d盘

	setlocale(LC_ALL, "chs");//注意系统信息中需要输出中文的敌方需要使用该函数
	HANDLE hFind;
	WIN32_FIND_DATA fData;

	//将参数中的路径保存在数组中，使用该数组作为路径进行文件遍历
	WCHAR FilePath[MAX_PATH] = { 0 };
	memcpy((void*)FilePath, Path, SizeOfFilePath);

	hFind = FindFirstFile(FilePath, &fData);
	if (hFind == (HANDLE)-1) return;

	do {
		if (!wcscmp(fData.cFileName, L".") || !wcscmp(fData.cFileName, L".."))//避免遍历隐藏的本目录路径以及父目录路径
			continue;
		//如果当前文件是文件夹，则需要递归遍历该文件夹中的文件
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WCHAR FilePathNext[MAX_PATH] = { 0 };

			StringCchPrintf(FilePathNext, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			FilePathNext[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(FilePathNext, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			StringCchCat(FilePathNext, MAX_PATH, L"\\*");//将遍历到文件名追加上去，形成新的路径

			int size = wcslen(FilePathNext) + 1;

			//递归遍历下一个文件夹
			DeleteVSGarbage(FilePathNext, size * 2);
		}
		else
		{
			//获取当前文件的全路径
			WCHAR VSFilePath[MAX_PATH] = { 0 };
			StringCchPrintf(VSFilePath, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			VSFilePath[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(VSFilePath, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			//获得当前文件的后缀名
			LPWSTR FileSuffix = PathFindExtension(VSFilePath);
			//比较后缀名
			if (!lstrcmp(FileSuffix, L".tlog") ||
				!lstrcmp(FileSuffix, L".obj") ||
				!lstrcmp(FileSuffix, L".log") ||
				!lstrcmp(FileSuffix, L".pch") ||
				!lstrcmp(FileSuffix, L".ilk") ||
				!lstrcmp(FileSuffix, L".pdb")
				)
			{
				DeleteFile(VSFilePath);
			}
		}
	} while (FindNextFile(hFind, &fData));
}

//删除垃圾文件（包括系统垃圾和浏览器垃圾）
void CMFCProcessTreeDlg::DeleteGarbage(WCHAR*Path, int SizeOfFilePath) {//暂时只能遍历d盘

	//提权函数从可以删除需要管理员权限才能删除的文件
	enableDebugPriv();

	setlocale(LC_ALL, "chs");//注意系统信息中需要输出中文的敌方需要使用该函数
	HANDLE hFind;
	WIN32_FIND_DATA fData;

	//将参数中的路径保存在数组中，使用该数组作为路径进行文件遍历
	WCHAR FilePath[MAX_PATH] = { 0 };
	memcpy((void*)FilePath, Path, SizeOfFilePath);

	hFind = FindFirstFile(FilePath, &fData);
	if (hFind == (HANDLE)-1) return;

	do {
		if (!wcscmp(fData.cFileName, L".") || !wcscmp(fData.cFileName, L".."))//避免遍历隐藏的本目录路径以及父目录路径
			continue;
		//如果当前文件是文件夹，则需要递归遍历该文件夹中的文件
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WCHAR FilePathNext[MAX_PATH] = { 0 };

			StringCchPrintf(FilePathNext, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			FilePathNext[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(FilePathNext, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			StringCchCat(FilePathNext, MAX_PATH, L"\\*");//将遍历到文件名追加上去，形成新的路径

			int size = wcslen(FilePathNext) + 1;
			
			//递归删除下一个文件夹
			DeleteGarbage(FilePathNext, size * 2);
		}
		else
		{
			WCHAR DeleteFilePath[MAX_PATH] = { 0 };
			StringCchPrintf(DeleteFilePath, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			DeleteFilePath[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(DeleteFilePath, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			DeleteFile(DeleteFilePath);

		}
	} while (FindNextFile(hFind, &fData));
}

//清除系统垃圾，包括windows垃圾 浏览器垃圾 vs垃圾
//按钮响应
void CMFCProcessTreeDlg::DeleteSysGarbage()
{

	UpdateData(TRUE);

	switch (m_ChoseButton)
	{
	case 7://系统垃圾
	{
		//清空指定目录下系统缓存文件
		int size = sizeof(L"C:\\Windows\\Temp\\*");
		DeleteGarbage(L"C:\\Windows\\Temp\\*", size);

		int size1 = sizeof(L"C:\\Users\\李嘉柏\\AppData\\Local\\Temp\\*");
		DeleteGarbage(L"C:\\Users\\李嘉柏\\AppData\\Local\\Temp\\*", size1);

		int size2 = sizeof(L"C:\\Users\\李嘉柏\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportQueue\\*");
		DeleteGarbage(L"C:\\Users\\李嘉柏\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportQueue\\*", size2);
		break;
	}
	case 8://浏览器垃圾
	{
		//C:\Users\李嘉柏\AppData\Local\Mozilla\Firefox\Profiles\mko98c82.default\cache2\entries   火狐浏览器网站缓存
		//删除指定目录浏览器缓存	
		int size3 = sizeof(L"C:\\Users\\李嘉柏\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\mko98c82.default\\cache2\\entries\\*");
		DeleteGarbage(L"C:\\Users\\李嘉柏\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\mko98c82.default\\cache2\\entries\\*", size3);
		break;
	}
	case 9://VS垃圾
	{
		//为测试仅仅删除执行项目中的垃圾
		int size4 = sizeof(L"E:\\c源码\\坦克大战 (升级版)\\*");
		DeleteVSGarbage(L"E:\\c源码\\坦克大战 (升级版)\\*", size4);
		//int size4 = sizeof(L"E:\\c源码\\*");
		//DeleteVSGarbage(L"E:\\c源码\\*", size4);
		break;
	}

	}
	UpdateData(FALSE);

}

//内存优化按键响应函数
void CMFCProcessTreeDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	//MEMORYSTATUS stcMemStatusEx = { 0 };
	//stcMemStatusEx.dwLength = sizeof(stcMemStatusEx);
	//gou

	DWORD dwPIDList[1000] = { 0 };
	DWORD bufSize = sizeof(dwPIDList);
	DWORD dwNeedSize = 0;
	EnumProcesses(dwPIDList, bufSize, &dwNeedSize);
	for (DWORD i = 0; i < dwNeedSize / sizeof(DWORD); i++)
	{
		//获得进程句柄
		HANDLE hProcess = OpenProcess(PROCESS_SET_QUOTA, false, dwPIDList[i]);
		//该函数用于设置特定进程占用的内存，如果最后两个参数均为-1，则该进程会尽可能释放多余的内存
		SetProcessWorkingSetSize(hProcess, -1, -1);
	}	
}

//清空回收站按钮响应函数
void CMFCProcessTreeDlg::RecycleBinClean()
{
	// TODO: 在此添加控件通知处理程序代码
	//初始化SHQUERYRBINFO结构
	SHQUERYRBINFO RecycleBinInformation;
	ZeroMemory(&RecycleBinInformation, sizeof(RecycleBinInformation));
	RecycleBinInformation.cbSize = sizeof(RecycleBinInformation);
	//查询回收站信息
	//SHQueryRecycleBin第一参数为要查询回收站的盘符或者文件夹,子文件夹
	//一般其根目录相同指向的回收站也是一样的
	//为NULL则指代所有回收站,和下面的SHEmptyRecycleBin第二参数相同
	if (SHQueryRecycleBin(NULL, &RecycleBinInformation) == S_OK)

	//清空回收站
	//SHEmptyRecycleBin第三参数如果要显示确认删除对话框和声音之类的东西置空既可
	SHEmptyRecycleBin(NULL, NULL, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
}

//显示pe头信息
void CMFCProcessTreeDlg::ShowPEHaederInfo(char* pBuf)
{
	//为了显示导入表字段做准备
	m_list.InsertItem(0, L"导入表字段----------------");
	m_list.SetItemText(0, 1, L"导入序号或导入函数名");
	m_list.InsertItem(0, L"");
	m_list.SetItemText(0, 1, L"");

	//获得dos头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//获得NT头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);

	//程序入口点
	TCHAR OEP[MAX_PATH] = { 0 };
	TCHAR IMAGE_BASE[MAX_PATH] = { 0 };
	TCHAR BaseOfCode[MAX_PATH] = { 0 };
	TCHAR NumberOfRvaAndSize[MAX_PATH] = { 0 };
	TCHAR RvaOfExportTable[MAX_PATH] = { 0 };
	TCHAR RvaOfImportTable[MAX_PATH] = { 0 };
	TCHAR RvaOfResourceTable[MAX_PATH] = { 0 };
	TCHAR RvaOfRelocationTable[MAX_PATH] = { 0 };
	TCHAR RvaOfTLSTable[MAX_PATH] = { 0 };
	TCHAR RvaOfDelayImportTable[MAX_PATH] = { 0 };


	//将数字转化为字符串
	_stprintf_s(OEP, MAX_PATH, _T("%x"), pNt->OptionalHeader.AddressOfEntryPoint);
	_stprintf_s(IMAGE_BASE, MAX_PATH, _T("%x"), pNt->OptionalHeader.ImageBase);
	_stprintf_s(BaseOfCode, MAX_PATH, _T("%x"), pNt->OptionalHeader.BaseOfCode);
	_stprintf_s(NumberOfRvaAndSize, MAX_PATH, _T("%x"), pNt->OptionalHeader.NumberOfRvaAndSizes);
	_stprintf_s(RvaOfExportTable, MAX_PATH, _T("%x"), pNt->OptionalHeader.DataDirectory[0].VirtualAddress);
	_stprintf_s(RvaOfImportTable, MAX_PATH, _T("%x"), pNt->OptionalHeader.DataDirectory[1].VirtualAddress);
	_stprintf_s(RvaOfResourceTable, MAX_PATH, _T("%x"), pNt->OptionalHeader.DataDirectory[2].VirtualAddress);
	_stprintf_s(RvaOfRelocationTable, MAX_PATH, _T("%x"), pNt->OptionalHeader.DataDirectory[5].VirtualAddress);
	_stprintf_s(RvaOfTLSTable, MAX_PATH, _T("%x"), pNt->OptionalHeader.DataDirectory[9].VirtualAddress);
	_stprintf_s(RvaOfDelayImportTable, MAX_PATH, _T("%x"), pNt->OptionalHeader.DataDirectory[13].VirtualAddress);


	//获得区段头
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNt);
	//用于保存区段名
	TCHAR SectionName[MAX_PATH];
	TCHAR SectionRva[MAX_PATH];
	TCHAR SectionFoa[MAX_PATH];


	while (!(pSectionHeader->Characteristics == 0) && (strcmp("", (const char*)pSectionHeader->Name)))
	{
		memset(SectionName, 0, MAX_PATH * 2);
		memset(SectionRva, 0, MAX_PATH * 2);
		memset(SectionFoa, 0, MAX_PATH * 2);
		_stprintf_s(SectionRva, MAX_PATH, _T("%x"), pSectionHeader->VirtualAddress);
		_stprintf_s(SectionFoa, MAX_PATH, _T("%x"), pSectionHeader->PointerToRawData);


		CHAR_TO_WCHAR((char*)pSectionHeader->Name, SectionName);

		m_list.InsertItem(0, SectionName);
		m_list.SetItemText(0, 1, SectionRva);
		m_list.SetItemText(0, 2, SectionFoa);

		pSectionHeader++;
	}

	m_list.InsertItem(0, L"区段表表字段----------------");
	m_list.SetItemText(0, 1, L"RVA");
	m_list.SetItemText(0, 2, L"FOA");
	m_list.InsertItem(0, L"");
	m_list.SetItemText(0, 1, L"");

	//将信息插入list控件，注意list控件插入顺序与显示顺序相反，
	m_list.InsertItem(0, L"延迟载入表起始地址RVA");
	m_list.SetItemText(0, 1, RvaOfDelayImportTable);
	m_list.InsertItem(0, L"TLS表起始地址RVA");
	m_list.SetItemText(0, 1, RvaOfTLSTable);
	m_list.InsertItem(0, L"重定位表起始地址RVA");
	m_list.SetItemText(0, 1, RvaOfRelocationTable);
	m_list.InsertItem(0, L"资源表起始地址RVA");
	m_list.SetItemText(0, 1, RvaOfResourceTable);
	m_list.InsertItem(0, L"导入表起始地址RVA");
	m_list.SetItemText(0, 1, RvaOfImportTable);
	m_list.InsertItem(0, L"导出表起始地址RVA");
	m_list.SetItemText(0, 1, RvaOfExportTable);
	m_list.InsertItem(0, L"目录表字段----------------");
	m_list.SetItemText(0, 1, L"RVA");
	m_list.InsertItem(0, L"");
	m_list.SetItemText(0, 1, L"");


	m_list.InsertItem(0, L"数据目录表中元素个数");
	m_list.SetItemText(0, 1, NumberOfRvaAndSize);
	m_list.InsertItem(0, L"起始代码RVA");
	m_list.SetItemText(0, 1, BaseOfCode);
	m_list.InsertItem(0, L"镜像基址");
	m_list.SetItemText(0, 1, IMAGE_BASE);
	m_list.InsertItem(0, L"程序入口点");
	m_list.SetItemText(0, 1, OEP);
	m_list.InsertItem(0, L"PE头字段----------------");
	m_list.SetItemText(0, 1, L"地址");

	UpdateData(FALSE);
}

//导入函数表
void CMFCProcessTreeDlg::ShowImportInfo(char* pBuf) {


	m_list.InsertItem(0, L"导出表字段----------------");
	m_list.SetItemText(0, 1, L"导出序号或导出函数名");
	m_list.InsertItem(0, L"");
	m_list.SetItemText(0, 1, L"");
	
	//找到导入位置，数据目录表的第二项（下标1）
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;

	//NT头
	PIMAGE_NT_HEADERS pNt =(PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_DATA_DIRECTORY pImportDir = &pNt->OptionalHeader.DataDirectory[1];

	//如果该程序没有该表，则结束
	if (pImportDir->VirtualAddress== 0)
		return;

	//计算导入表的文件偏移FOA
	DWORD dwImportFOA = RVAtoFOA(pImportDir->VirtualAddress, pBuf);
	//具体在文件中的位置
	PIMAGE_IMPORT_DESCRIPTOR pImport =(PIMAGE_IMPORT_DESCRIPTOR)(dwImportFOA + pBuf);
	
	char modulename[MAX_PATH];//模块名称char
	TCHAR ModuleName[MAX_PATH];//模块名称wchar_t
	TCHAR Ordinal[MAX_PATH];//表示序号导入的函数
	char importfuncname[MAX_PATH];//导入函数名称char
	TCHAR ImportFuncName[MAX_PATH];

	//遍历导入表
	while (pImport->Name)
	{
		//将存储模块名的缓冲区清零，为下一次输入做准备
		memset(modulename, 0, MAX_PATH);
		memset(ModuleName, 0, MAX_PATH);
		memset(Ordinal, 0, MAX_PATH);
		memset(importfuncname, 0, MAX_PATH);
		memset(ImportFuncName, 0, MAX_PATH);

		//获得模块名
		strcpy_s(modulename,sizeof(modulename), (RVAtoFOA(pImport->Name, pBuf) + pBuf));
		//将模块名转为大写
		CHAR_TO_WCHAR(modulename, ModuleName);
		//插入模块的名称
		m_list.InsertItem(0, ModuleName);

		//通过INT来遍历
		PIMAGE_THUNK_DATA pINT =(PIMAGE_THUNK_DATA)(RVAtoFOA(pImport->OriginalFirstThunk, pBuf) + pBuf);
		while (pINT->u1.AddressOfData)
		{
			//判断到方式，如果IMAGE_THUNK_DATA最高为为1说明是序号导入
			//否则是符号导入
			if (pINT->u1.AddressOfData & 0x80000000)
			{
				//序号导入
				_stprintf_s(Ordinal, MAX_PATH, _T("%d"), pINT->u1.Ordinal&0xFFFF);
				m_list.InsertItem(1, L"");
				m_list.SetItemText(1, 1, Ordinal);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(pINT->u1.AddressOfData, pBuf) + pBuf);
				//获得导入函数名
				strcpy_s(importfuncname, sizeof(importfuncname), (pName->Name));
				//将函数名转为wchar_t
				CHAR_TO_WCHAR(importfuncname, ImportFuncName);
			
				//插入函数的名称
				m_list.InsertItem(1, L"");
				m_list.SetItemText(1, 1, ImportFuncName);

				//注意上面的插入序号与插入函数名是或关系，所以使用相同的插入模式就可以，即 1   1,1
			}
			//下一个导入函数
			pINT++;
		}
		//下一个导入的dll
		pImport++;
	}
	UpdateData(FALSE);
}

//导出表信息
void CMFCProcessTreeDlg::ShowExportInfo(char* pBuf) 
{
	m_list.InsertItem(0, L"资源表字段----------------");
	m_list.SetItemText(0, 1, L"资源序号或资源名");
	m_list.SetItemText(0, 2, L"资源的RVA");
	m_list.InsertItem(0, L"");
	m_list.SetItemText(0, 1, L"");

	//找到导出位置，数据目录表的第一项（下标0）
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt =(PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	//获得导出表的RVA
	PIMAGE_DATA_DIRECTORY pExportDir = &pNt->OptionalHeader.DataDirectory[0];

	//如果该程序没有该表，则结束
	if (pExportDir->VirtualAddress == 0)
		return;

	//计算导出表的文件偏移FOA
	DWORD dwExportFOA = RVAtoFOA(pExportDir->VirtualAddress, pBuf);
	//具体在文件中的位置
	PIMAGE_EXPORT_DIRECTORY pExport =(PIMAGE_EXPORT_DIRECTORY)(dwExportFOA + pBuf);


	char exmodulename[MAX_PATH];//模块名称char
	TCHAR ExModuleName[MAX_PATH];//模块名称wchar_t
	TCHAR Ordinal[MAX_PATH];//表示序号导出的函数
	TCHAR AddressOfFunc[MAX_PATH];//函数地址


	//模块名
	strcpy_s(exmodulename, sizeof(exmodulename), (RVAtoFOA(pExport->Name, pBuf) + pBuf));
	//将模块名转为大写
	CHAR_TO_WCHAR(exmodulename,ExModuleName);
	//插入导出模块名
	m_list.InsertItem(0, ExModuleName);


	//遍历导出表
	DWORD dwFunAddrCount = pExport->NumberOfFunctions;//函数数量
	DWORD dwFunNameCount = pExport->NumberOfNames;//函数名数量

	PDWORD pFunAddr = (PDWORD)(RVAtoFOA(pExport->AddressOfFunctions, pBuf) + pBuf);
	PDWORD pFunName = (PDWORD)(RVAtoFOA(pExport->AddressOfNames, pBuf) + pBuf);
	PWORD pFunOrdinal = (PWORD)(RVAtoFOA(pExport->AddressOfNameOrdinals, pBuf) + pBuf);


	for (int i = 0; i < dwFunAddrCount; i++)
	{
		memset(Ordinal, 0, MAX_PATH);
		memset(AddressOfFunc, 0, MAX_PATH);

		//如果有无效地址，直接下一个
		if (pFunAddr[i] == 0)
		{
			continue;
		}

		//输出函数地址
		_stprintf_s(AddressOfFunc, MAX_PATH, _T("%x"), (pFunAddr[i]));
		m_list.InsertItem(1,AddressOfFunc);

		//判断是否是符号导出（是否有函数名字）
		//遍历序号表，看是否存在此序号（地址表下标 i ）
		
		bool bFalg = false; //标识是否有名字
		for (int j = 0; j < dwFunNameCount; j++)
		{
			if (i == pFunOrdinal[j])
			{
				//存在说明有函数名称
				bFalg = true;
				DWORD dwNameAddr = pFunName[j];
				char* pexfuncname = RVAtoFOA(dwNameAddr, pBuf) + pBuf;

				USES_CONVERSION;
				TCHAR*pExFuncName = A2W(pexfuncname);

				//m_list.InsertItem(1, L"");
				m_list.SetItemText(1, 1, pExFuncName);
				
				break;
			}
		}
		if (!bFalg)//直接输出序号
		{
			_stprintf_s(Ordinal, MAX_PATH, _T("%d"),(i + pExport->Base));
			//m_list.InsertItem(1, L"");
			m_list.SetItemText(1, 1, Ordinal);
		}
	}
	UpdateData(FALSE);
}

//资源表信息
void CMFCProcessTreeDlg::ShowResourceInfo(char* pBuf)
{
	m_list.InsertItem(0, L"重定块地址----------------");
	m_list.SetItemText(0, 1, L"重定位块大小");
	m_list.SetItemText(0, 2, L"需要重定位的数量");
	m_list.SetItemText(0, 3, L"需要被重定位的数据的rva");
	m_list.InsertItem(0, L"");
	m_list.SetItemText(0, 1, L"");

	//找到资源位置，数据目录表的第三项（下标2）
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt =(PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	//资源表
	PIMAGE_DATA_DIRECTORY pResDir = &pNt->OptionalHeader.DataDirectory[2];

	//如果该程序没有该表，则结束
	if (pResDir->VirtualAddress == 0)
		return;

	//计算资源表的文件偏移FOA
	DWORD dwResFOA = RVAtoFOA(pResDir->VirtualAddress, pBuf);
	//具体在文件中的位置
	PIMAGE_RESOURCE_DIRECTORY pResRoot =(PIMAGE_RESOURCE_DIRECTORY)(dwResFOA + pBuf);

	//第一层，资源的种类
	//资源种类数量
	DWORD dwCount1 = pResRoot->NumberOfIdEntries +pResRoot->NumberOfNamedEntries;
	//找到资源种类数组
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry1 =(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResRoot + 1);
	for (int i1 = 0; i1 < dwCount1; i1++)
	{
		//判断资源命名方式（pEntry1->NameIsString为1说明是字符串命名，否则是数字命名）
		if (pEntry1->NameIsString)
		{
			//注意资源块中的偏移是相对于资源块头地址而言的
			PIMAGE_RESOURCE_DIR_STRING_U pName =(PIMAGE_RESOURCE_DIR_STRING_U)(pEntry1->NameOffset + (DWORD)pResRoot);
			WCHAR* pNameBuf = new WCHAR[pName->Length + 1]{};
			memcpy(pNameBuf, pName->NameString, pName->Length * 2);
			
			//插入资源种类(名称)**************************************************************************************
			m_list.InsertItem(0, pNameBuf);

			//printf("------资源种类：%S------\n", pNameBuf);
			delete[] pNameBuf;
		}
		else
		{
			if (pEntry1->Id >= 1 && pEntry1->Id <= 16)
			{
				wchar_t NameOfResType[16][20] = { L"鼠标指针",L"位图",L"图标",L"菜单",L"对话框",L"字符串列表",L"字体目录"
								,                L"字体",L"快捷键",L"非格式化资源",L"消息列表",L"鼠标指针组",L"13",L"图标",L"15",L"版本信息" };
				int n = (pEntry1->Id) - 1;
				//插入资源种类（序号)**************************************************************************************
				m_list.InsertItem(0, NameOfResType[n]);
			}
			else
			{
				//printf("-------资源种类：%d-------- \n", pEntry1->Id);
				WCHAR* pNameNumOfRes = new WCHAR[MAX_PATH]{};
				_stprintf_s(pNameNumOfRes, MAX_PATH, _T("%d"), pEntry1->Id);
				//插入资源种类（序号)**************************************************************************************
				m_list.InsertItem(0, pNameNumOfRes);
				delete[] pNameNumOfRes;
			}

		}
		//判断是否有下一层(pEntry1->DataIsDirectory为1说明有下一层)
		if (pEntry1->DataIsDirectory)
		{
			//第二层（某种资源的个数）
			PIMAGE_RESOURCE_DIRECTORY pRes2 =(PIMAGE_RESOURCE_DIRECTORY)(pEntry1->OffsetToDirectory + (DWORD)pResRoot);
			DWORD dwCount2 = pRes2->NumberOfIdEntries +pRes2->NumberOfNamedEntries;
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry2 =(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRes2 + 1);
			for (int i2 = 0; i2 < dwCount2; i2++)
			{
				//某种资源的每一个资源的名字
				//比如第一种资源叫PNG，那么这里遍历的就是
				//PNG这种资源的每一个
				//判断资源命名方式（pEntry1->NameIsString为1说明是字符串命名，否则是数字命名）
				if (pEntry2->NameIsString)
				{
					PIMAGE_RESOURCE_DIR_STRING_U pName =(PIMAGE_RESOURCE_DIR_STRING_U)(pEntry2->NameOffset + (DWORD)pResRoot);
					WCHAR* pNameBuf = new WCHAR[pName->Length + 1]{};
					memcpy(pNameBuf, pName->NameString, pName->Length * 2);
					//插入资源名(名称)**************************************************************************************
					m_list.InsertItem(1, L"");
					m_list.SetItemText(1, 1, pNameBuf);
					//printf("------第二层资源名：%S------", pNameBuf);
					delete[] pNameBuf;
				}
				else
				{
					//插入资源名(序号)**************************************************************************************
					//printf("-------第二层资源名：%d-------- ", pEntry2->Id);
					WCHAR* pNameNumOfRes = new WCHAR[MAX_PATH]{};
					_stprintf_s(pNameNumOfRes, MAX_PATH, _T("%d"), pEntry2->Id);
					m_list.InsertItem(1, L"");
					m_list.SetItemText(1, 1, pNameNumOfRes);
					delete[] pNameNumOfRes;
				}
				//判断是否有下一层（第三层） //暂时不对第三层的内容输出
				if (pEntry2->DataIsDirectory)
				{
					PIMAGE_RESOURCE_DIRECTORY pRes3 =(PIMAGE_RESOURCE_DIRECTORY)(pEntry2->OffsetToDirectory + (DWORD)pResRoot);
					//第三层此值就是1
					DWORD dwCount3 = pRes3->NumberOfIdEntries +pRes3->NumberOfNamedEntries;

					PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry3 =(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRes3 + 1);

					PIMAGE_RESOURCE_DATA_ENTRY pData =(PIMAGE_RESOURCE_DATA_ENTRY)(pEntry3->OffsetToData + (DWORD)pResRoot);

					//char* pDataBuf = RVAtoFOA(pData->OffsetToData, pBuf) + pBuf;

					//资源位置的偏移
					TCHAR* RvaDataOfRes = new TCHAR[MAX_PATH];
					//输出资源二进制数据的rva*********************************************************************************
					_stprintf_s(RvaDataOfRes, 10, _T("%x"), pData->OffsetToData);
					m_list.SetItemText(1, 2, RvaDataOfRes);
					delete[]RvaDataOfRes;
				}
				//某种类的下一个
				pEntry2++;
			}//第二层

		}
		//下一个种类
		pEntry1++;
	}//第一层
}

//重定位表
void CMFCProcessTreeDlg::ShowRelocationInfo(char* pBuf)
{
	m_list.InsertItem(0, L"TLS源数据起始RVA----------------");
	m_list.SetItemText(0, 1, L"TLS源数据结束RVA");
	m_list.SetItemText(0, 2, L"回调函数表VA");
	m_list.InsertItem(0, L"");
	m_list.SetItemText(0, 1, L"");

	//找到重定位表位置
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt =(PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	//重定义表的位置
	PIMAGE_DATA_DIRECTORY pRelocDir = &pNt->OptionalHeader.DataDirectory[5];
	
	//如果该程序没有该表，则结束
	if (pRelocDir->VirtualAddress == 0)
		return;

	//计算重定位表的文件偏移FOA
	DWORD dwRelocFOA = RVAtoFOA(pRelocDir->VirtualAddress, pBuf);
	//重定位具体在文件中的位置
	PIMAGE_BASE_RELOCATION pReloc =(PIMAGE_BASE_RELOCATION)(dwRelocFOA + pBuf);

	struct TypeOffset
	{
		WORD offset : 12;
		WORD type : 4;
	};
	//遍历重定位
	int n = 1;
	while (pReloc->SizeOfBlock)
	{
		//遍历每一块内的重定位项
		TypeOffset* pOffset = (TypeOffset*)(pReloc + 1);
	
		//重定位项的个数
		DWORD dwCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		
		printf("第%d块，VirtualAddress:%08X ，SizeOfBlock：%d ",n++, pReloc->VirtualAddress, pReloc->SizeOfBlock);
		
		//重定位块地址
		WCHAR* pAddressOfReBlock = new WCHAR[MAX_PATH]{};
		_stprintf_s(pAddressOfReBlock, MAX_PATH, _T("%x"), pReloc->VirtualAddress);
		//**************************************************************************************
		m_list.InsertItem(0, pAddressOfReBlock);
		delete[] pAddressOfReBlock;
		

		//重定位块大小
		WCHAR* pSizeOfReBlock = new WCHAR[MAX_PATH]{};
		_stprintf_s(pSizeOfReBlock, MAX_PATH, _T("%d"), pReloc->SizeOfBlock);
		//**************************************************************************************
		m_list.SetItemText(0, 1, pSizeOfReBlock);
		delete[] pSizeOfReBlock;

		//重定位块中需要重定位数量
		WCHAR* pNumOfReLocation = new WCHAR[MAX_PATH]{};
		_stprintf_s(pNumOfReLocation, MAX_PATH, _T("%d"), dwCount);
		//**************************************************************************************
		m_list.SetItemText(0, 2, pNumOfReLocation);
		delete[] pNumOfReLocation;



		for (int i = 0; i < dwCount; i++)
		{
			//type==3,说明需要修正4个字节
			if (pOffset->type == 3)
			{
				DWORD dwDataRVA = pReloc->VirtualAddress +pOffset->offset;

				DWORD dwDataFOA = RVAtoFOA(dwDataRVA, pBuf);
				//需要重定位数据的rva
				PDWORD pData = (PDWORD)(dwDataFOA + pBuf);
				
				WCHAR* pRvaOfRelocation = new WCHAR[MAX_PATH]{};

				_stprintf_s(pRvaOfRelocation, MAX_PATH, _T("%X"), dwDataRVA);
				//插入资源种类（序号)**************************************************************************************
				m_list.InsertItem(1, L"");
				m_list.SetItemText(1, 1, L"");
				m_list.SetItemText(1, 2, L"");
				m_list.SetItemText(1, 3, pRvaOfRelocation);		
				delete[] pRvaOfRelocation;
			
			}
			if (i == 5)//只输出5个需要重定位的位置
			{//测试用的
				break;
			}
			//下一个重定位项
			pOffset++;
		}
		//下一重定位块
		pReloc = (PIMAGE_BASE_RELOCATION)
			((DWORD)pReloc + pReloc->SizeOfBlock);
	}
}
//TLS表
void CMFCProcessTreeDlg::ShowTLSInfo(char* pBuf) {
	
	m_list.InsertItem(0, L"延迟输入模块名----------------");
	m_list.SetItemText(0, 1, L"延迟输入函数序号或函数名");

	m_list.InsertItem(0, L"");
	m_list.SetItemText(0, 1, L"");

	//找到重TLS表位置
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	//TLS表的位置
	PIMAGE_DATA_DIRECTORY pTLSRva = &pNt->OptionalHeader.DataDirectory[9];
	
	//如果该程序没有TLS表，则结束
	if (pTLSRva->VirtualAddress == 0)
		return;

	//计算TLS表的文件偏移FOA
	DWORD dwTLSFOA = RVAtoFOA(pTLSRva->VirtualAddress, pBuf);
	//TLS具体在文件中的位置
	IMAGE_TLS_DIRECTORY* pTLS = (IMAGE_TLS_DIRECTORY*)(dwTLSFOA + pBuf);

	//源数据起始地址
	WCHAR* pTLSStart = new WCHAR[MAX_PATH]{};
	_stprintf_s(pTLSStart, MAX_PATH, _T("%x"), pTLS->StartAddressOfRawData);
	//**************************************************************************************
	 m_list.InsertItem(0, pTLSStart);
	delete[] pTLSStart;

	//原数据终止地址	
	WCHAR* pTLSEnd = new WCHAR[MAX_PATH]{};
	_stprintf_s(pTLSEnd, MAX_PATH, _T("%x"), pTLS->EndAddressOfRawData);
	//**************************************************************************************
	m_list.SetItemText(0, 1, pTLSEnd);
	delete[] pTLSEnd;
	
	//回调函数地址表的VA
	WCHAR* pTLSCallBack = new WCHAR[MAX_PATH]{};
	_stprintf_s(pTLSCallBack, MAX_PATH, _T("%x"), pTLS->AddressOfCallBacks);
	//**************************************************************************************
	m_list.SetItemText(0, 2, pTLSCallBack);
	delete[] pTLSCallBack;
}

//延迟加载表
void CMFCProcessTreeDlg::ShowDelayInfo(char* pBuf)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	
	//延迟导入表rva
	PIMAGE_DATA_DIRECTORY pDelayDir = &pNt->OptionalHeader.DataDirectory[13];
	
	//如果该程序没有延迟导入表，则结束
	if (pDelayDir->VirtualAddress == 0)
		return;

	//计算导入表的文件偏移FOA
	DWORD dwDelayFOA = RVAtoFOA(pDelayDir->VirtualAddress, pBuf);
	//具体在文件中的位置
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelay = (PIMAGE_DELAYLOAD_DESCRIPTOR)(dwDelayFOA + pBuf);

	char modulename[MAX_PATH];//模块名称char
	TCHAR ModuleName[MAX_PATH];//模块名称wchar_t
	TCHAR Ordinal[MAX_PATH];//表示序号导入的函数
	char importfuncname[MAX_PATH];//导入函数名称char
	TCHAR ImportFuncName[MAX_PATH];

	//遍历延迟导入表
	while (pDelay->DllNameRVA)
	{
		//将存储模块名的缓冲区清零，为下一次输入做准备
		memset(modulename, 0, MAX_PATH);
		memset(ModuleName, 0, MAX_PATH);
		memset(Ordinal, 0, MAX_PATH);
		memset(importfuncname, 0, MAX_PATH);
		memset(ImportFuncName, 0, MAX_PATH);

		//获得模块名
		strcpy_s(modulename, sizeof(modulename), (RVAtoFOA(pDelay->DllNameRVA, pBuf) + pBuf));
		//将模块名转为大写
		CHAR_TO_WCHAR(modulename, ModuleName);
		//插入模块的名称
		m_list.InsertItem(0, ModuleName);

		//通过INT来遍历
		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(RVAtoFOA(pDelay->ImportNameTableRVA, pBuf) + pBuf);
		while (pINT->u1.AddressOfData)
		{
			//判断到方式，如果IMAGE_THUNK_DATA最高为为1说明是序号导入
			//否则是符号导入
			if (pINT->u1.AddressOfData & 0x80000000)
			{
				//序号导入
				_stprintf_s(Ordinal, MAX_PATH, _T("%d"), pINT->u1.Ordinal & 0xFFFF);
				m_list.InsertItem(1, L"");
				m_list.SetItemText(1, 1, Ordinal);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(pINT->u1.AddressOfData, pBuf) + pBuf);
				//获得导入函数名
				strcpy_s(importfuncname, sizeof(importfuncname), (pName->Name));
				//将函数名转为wchar_t
				CHAR_TO_WCHAR(importfuncname, ImportFuncName);

				//插入函数的名称
				m_list.InsertItem(1, L"");
				m_list.SetItemText(1, 1, ImportFuncName);
				//注意上面的插入序号与插入函数名是或关系，所以使用相同的插入模式就可以，即 1   1,1
			}
			//下一个导入函数
			pINT++;
		}
		//下一个导入的dll
		pDelay++;
	}
	UpdateData(FALSE);
}

//PE文件解析按钮响应函数
void CMFCProcessTreeDlg::PEFileParser()
{
	// TODO: 在此添加控件通知处理程序代码
	m_list.DeleteAllItems();
	UpdateData(FALSE);
	
	//弹出对话框，选择指定文件，返回文件绝对路径
	CString strFile = _T("");
	CFileDialog dlgFile(TRUE, NULL, NULL, OFN_HIDEREADONLY,
		_T("Describe Files All Files (*.*)|*.*||"), NULL);
	if (dlgFile.DoModal())
	{
		//获得指定文件的绝对路径
		strFile = dlgFile.GetPathName();
	}

	//正文数据放在buff中
	wchar_t FilePathUNICODE[MAX_PATH] = { 0 };
	memcpy(FilePathUNICODE, strFile.GetBuffer(), (strFile.GetLength() + 1) * sizeof(TCHAR));

	//获得ascii的程序路径
	char FilePathASCII[MAX_PATH] = { 0 };
	WCHAR_TO_CHAR(FilePathUNICODE, FilePathASCII);

	//将文件读取进入内存，并获取保存文件内容的内存首地址
	char* pBuf = ReadFileToMemory(FilePathASCII);
	if (IsPeFile(pBuf))
	{
		//主语函数调用的顺序不能变，否则不能正常显示
		ShowDelayInfo(pBuf);
		ShowTLSInfo(pBuf);//TLS表
		ShowRelocationInfo(pBuf);//重定位表
		ShowResourceInfo(pBuf);//资源表信息
		ShowExportInfo(pBuf);//导出表信息
		ShowImportInfo(pBuf);//导入表信息
		ShowPEHaederInfo(pBuf);//显示pe头信息
	}
	delete[] pBuf;
}

//枚举服务
void CMFCProcessTreeDlg::ErgodicServices()
{
	enableDebugPriv();
	//打开服务管理器
	SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	DWORD dwServicesNum = 0;
	DWORD dwSize = 0;
	EnumServicesStatusEx(hScm,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		NULL,
		0,
		&dwSize,
		&dwServicesNum,
		NULL, NULL);

	LPENUM_SERVICE_STATUS_PROCESS pEnumService = (LPENUM_SERVICE_STATUS_PROCESS) new char[dwSize];
	bool bStatus = FALSE;
	bStatus = EnumServicesStatusEx(hScm,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		(PBYTE)pEnumService,
		dwSize,
		&dwSize,
		&dwServicesNum,
		NULL, NULL);

	m_list.InsertItem(0, L"服务名");
	m_list.SetItemText(0, 1,L"服务类型");
	m_list.SetItemText(0, 2, L"服务状态");
	m_list.SetItemText(0, 3, L"服务启动类型");
	m_list.SetItemText(0, 4, L"服务路径");

	//遍历信息
	for (DWORD i = 0; i < dwServicesNum; i++)
	{
		//服务名
		m_list.InsertItem(1, pEnumService[i].lpDisplayName);
	
		//服务类型
		//std::cout << pEnumService[i].ServiceStatusProcess.dwServiceType<< "\n" << std::endl;
		WCHAR* pSerVicesType = new WCHAR[MAX_PATH]{};
		_stprintf_s(pSerVicesType, MAX_PATH, _T("%x"), pEnumService[i].ServiceStatusProcess.dwServiceType);
		//**************************************************************************************
		m_list.SetItemText(1, 1, pSerVicesType);
		delete[] pSerVicesType;

		//服务状态
		//std::cout << pEnumService[i].ServiceStatusProcess.dwCurrentState << "\n" << std::endl;
		WCHAR* pSerVicesState = new WCHAR[MAX_PATH]{};
		_stprintf_s(pSerVicesState, MAX_PATH, _T("%x"), pEnumService[i].ServiceStatusProcess.dwCurrentState);
		//**************************************************************************************
		m_list.SetItemText(1, 2, pSerVicesState);
		delete[] pSerVicesState;

		//打开服务
		SC_HANDLE hService = OpenService(hScm,pEnumService[i].lpServiceName,SERVICE_QUERY_CONFIG);

		QueryServiceConfig(hService,NULL,0,&dwSize);	
		LPQUERY_SERVICE_CONFIG pServiceConfig = (LPQUERY_SERVICE_CONFIG)new char[dwSize];
		QueryServiceConfig(hService,pServiceConfig, dwSize, &dwSize);

		//获取服务启动类型
		//std::cout << pServiceConfig->dwStartType << "\n" << std::endl;

		WCHAR* pSerVicesStartType = new WCHAR[MAX_PATH]{};
		_stprintf_s(pSerVicesStartType, MAX_PATH, _T("%x"), pServiceConfig->dwStartType);
		//**************************************************************************************
		m_list.SetItemText(1, 3, pSerVicesStartType);
		delete[] pSerVicesStartType;

		//服务路径
		//std::cout << pServiceConfig->lpBinaryPathName <<"\n"<< std::endl;
		m_list.SetItemText(1, 4, pServiceConfig->lpBinaryPathName);

		//std::cout <<"*****************************************\n" << std::endl;
	
		CloseServiceHandle(hService);
	
	}
	CloseServiceHandle(hScm);
}

//开启服务，关闭服务
void CMFCProcessTreeDlg::ChangeServicesState()
{
	// TODO: 在此添加控件通知处理程序代码
	CString str;
	int nId;

	//得到鼠标点击在list控件中的内容
	//首先得到点击的位置
	POSITION pos = m_list.GetFirstSelectedItemPosition();
	//得到行号，通过POSITION转化
	nId = (int)m_list.GetNextSelectedItem(pos);
	//得到列中的内容（0表示第一列，同理1,2,3...表示第二，三，四...列）
	str = m_list.GetItemText(nId, 0);

	SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	DWORD dwServicesNum = 0;
	DWORD dwSize = 0;
	EnumServicesStatusEx(hScm,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		NULL,
		0,
		&dwSize,
		&dwServicesNum,
		NULL, NULL);

	LPENUM_SERVICE_STATUS_PROCESS pEnumService = (LPENUM_SERVICE_STATUS_PROCESS) new char[dwSize];
	bool bStatus = FALSE;
	bStatus = EnumServicesStatusEx(hScm,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		(PBYTE)pEnumService,
		dwSize,
		&dwSize,
		&dwServicesNum,
		NULL, NULL);


	//遍历信息
	for (DWORD i = 0; i < dwServicesNum; i++)
	{
		//服务名
		if (pEnumService[i].lpDisplayName == str)
		{
			//打开服务
			SC_HANDLE hService = OpenService(hScm,pEnumService[i].lpServiceName, SC_MANAGER_ALL_ACCESS);

			UpdateData(TRUE);

			switch (ServiceChose)
			{
			case 0://开启服务
			{
				if (BOOL start = StartServiceA(hService, 0, NULL))
				{
					//开启成功
					MessageBox(L"开启服务成功");
				}
				else 
				{
					//开启失败
					MessageBox(L"开启服务失败");
				}
				break;
			}
			
			case 1://关闭服务
			{
				SERVICE_STATUS   ServiceStatus;
				QueryServiceStatus(hService, &ServiceStatus);

				if (ServiceStatus.dwCurrentState == SERVICE_RUNNING || ServiceStatus.dwCurrentState == SERVICE_PAUSED)
				{
					if (BOOL start = ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus))

					{
						//结束成功
						MessageBox(L"结束服务成功");
					}
					else
					{
						//结束失败
						MessageBox(L"结束服务失败");
					}
				}
				break;
			}			
			}
			CloseServiceHandle(hService);
		}
	}
	CloseServiceHandle(hScm);
}

//用于响应MD5杀毒按钮，指定文件夹作为保存病毒的路径，用于测试MD5杀毒
void CMFCProcessTreeDlg::MD5KillVirus() {
	int size = sizeof(L"C:\\Users\\李嘉柏\\Desktop\\virusKill\\*");
	MD5KillVirusFunc(L"C:\\Users\\李嘉柏\\Desktop\\virusKill\\*", size);
}

//响应全路径杀毒按钮，指定文件夹作为保存病毒的路径，用于测试MD5杀毒
void CMFCProcessTreeDlg::AllRoadVirusKill()
{
	// TODO: 在此添加控件通知处理程序代码
	int size = sizeof(L"C:\\Users\\李嘉柏\\Desktop\\virusKill2\\*");
	AllRoadVirusKillFunc(L"C:\\Users\\李嘉柏\\Desktop\\virusKill2\\*", size);
}
//MD5杀毒
void CMFCProcessTreeDlg::MD5KillVirusFunc(WCHAR*Path, int SizeOfFilePath)
{
	// TODO: 在此添加控件通知处理程序代码

	m_list.DeleteAllItems();
	UpdateData(FALSE);

	setlocale(LC_ALL, "chs");//注意系统信息中需要输出中文的敌方需要使用该函数
	HANDLE hFind;
	WIN32_FIND_DATA fData;

	//将参数中的路径保存在数组中，使用该数组作为路径进行文件遍历
	WCHAR FilePath[MAX_PATH] = { 0 };
	memcpy((void*)FilePath, Path, SizeOfFilePath);

	hFind = FindFirstFile(FilePath, &fData);
	if (hFind == (HANDLE)-1) return;

	do {
		if (!wcscmp(fData.cFileName, L".") || !wcscmp(fData.cFileName, L".."))//避免遍历隐藏的本目录路径以及父目录路径
			continue;
		//如果当前文件是文件夹，则需要递归遍历该文件夹中的文件
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WCHAR FilePathNext[MAX_PATH] = { 0 };

			StringCchPrintf(FilePathNext, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			FilePathNext[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(FilePathNext, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			StringCchCat(FilePathNext, MAX_PATH, L"\\*");//将遍历到文件名追加上去，形成新的路径

			int size = wcslen(FilePathNext) + 1;
			//递归遍历下一个文件夹
			MD5KillVirusFunc(FilePathNext, size * 2);
		}
		else
		{
			//打开从保存病毒md5的文件，获取病毒md5
			HANDLE hFile2 = CreateFile(L"C:\\Users\\李嘉柏\\Desktop\\MD5杀毒.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD dwPos2 = SetFilePointer(hFile2, 0, NULL, FILE_BEGIN);
			char MD5OfVirus[5][33] = {};//该数组用于保存病毒md5 注意该数组的5决定了最多可以存储5个病毒MD5
			DWORD dwReads;
			ReadFile(hFile2, MD5OfVirus, 33 * 5, &dwReads, NULL);//将文件中病毒的MD5指读取到内存中
			CloseHandle(hFile2);

			//获得被遍历到的文件的全地址
			WCHAR GetFilePath[MAX_PATH] = { 0 };
			StringCchPrintf(GetFilePath, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			GetFilePath[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(GetFilePath, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
	
			//将路径转为char类型
			char GetFilePathASCII[MAX_PATH] = { 0 };
			WCHAR_TO_CHAR(GetFilePath, GetFilePathASCII)
				
			//为了方便计算MD5值这里将疑似病毒文件的全路径进行md5计算，作为文件的md5值
			MD5 md5(GetFilePathASCII);
			using namespace std;
			string result = md5.md5();
			char md5code[33];
			result.copy(md5code, 32, 0);
			*(md5code + 32) = '\0';

			for(int i=0;i<5;i++)
			{
				if (!memcmp(md5code, (MD5OfVirus + i), 33))//如果命中了病毒的md5
				{
					UpdateData(TRUE);
					m_list.InsertItem(0, GetFilePath);//显示病毒路径
					UpdateData(FALSE);
					DeleteFile(GetFilePath);//删除病毒文件
					break;
				}		
			}
		}
	} while (FindNextFile(hFind, &fData));
}
//全路径杀毒
void CMFCProcessTreeDlg::AllRoadVirusKillFunc(WCHAR*Path, int SizeOfFilePath) {

	m_list.DeleteAllItems();
	UpdateData(FALSE);

	setlocale(LC_ALL, "chs");//注意系统信息中需要输出中文的敌方需要使用该函数
	HANDLE hFind;
	WIN32_FIND_DATA fData;

	//将参数中的路径保存在数组中，使用该数组作为路径进行文件遍历
	WCHAR FilePath[MAX_PATH] = { 0 };
	memcpy((void*)FilePath, Path, SizeOfFilePath);

	hFind = FindFirstFile(FilePath, &fData);
	if (hFind == (HANDLE)-1) return;

	do {
		if (!wcscmp(fData.cFileName, L".") || !wcscmp(fData.cFileName, L".."))//避免遍历隐藏的本目录路径以及父目录路径
			continue;
		//如果当前文件是文件夹，则需要递归遍历该文件夹中的文件
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WCHAR FilePathNext[MAX_PATH] = { 0 };

			StringCchPrintf(FilePathNext, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			FilePathNext[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(FilePathNext, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			StringCchCat(FilePathNext, MAX_PATH, L"\\*");//将遍历到文件名追加上去，形成新的路径

			int size = wcslen(FilePathNext) + 1;
			//递归遍历下一个文件夹
			AllRoadVirusKillFunc(FilePathNext, size * 2);
		}
		else
		{
			//打开从保存病毒md5的文件，获取病毒md5
			HANDLE hFile2 = CreateFile(L"C:\\Users\\李嘉柏\\Desktop\\全路径杀毒.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD dwPos2 = SetFilePointer(hFile2, 0, NULL, FILE_BEGIN);
			char MD5OfVirus[5][33] = {};//该数组用于保存病毒md5 注意该数组的5决定了最多可以存储5个病毒MD5
			DWORD dwReads;
			ReadFile(hFile2, MD5OfVirus, 33 * 5, &dwReads, NULL);
			CloseHandle(hFile2);

			//获得被遍历到的文件的全地址
			WCHAR GetFilePath[MAX_PATH] = { 0 };
			StringCchPrintf(GetFilePath, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			GetFilePath[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(GetFilePath, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径

			//将路径转为char类型
			char GetFilePathASCII[MAX_PATH] = { 0 };
			WCHAR_TO_CHAR(GetFilePath, GetFilePathASCII)

		    //这里也是计算文件全路径的MD5值，只不过对应病毒MD5在计算过程中是与路径相关的，
			//所以如果命中指定文件名位于指定路径下，则该文件会被当作病毒处理
			MD5 md5(GetFilePathASCII);
			using namespace std;
			string result = md5.md5();
			char md5code[33];
			result.copy(md5code, 32, 0);
			*(md5code + 32) = '\0';

			for (int i = 0; i < 5; i++)
			{
				if (!memcmp(md5code, (MD5OfVirus + i), 33))//如果命中了病毒的md5
				{
					UpdateData(TRUE);
					m_list.InsertItem(0, GetFilePath);//显示病毒路径
					UpdateData(FALSE);
					DeleteFile(GetFilePath);//删除病毒文件
					break;
				}
			}
		}
	} while (FindNextFile(hFind, &fData));
}

//关机
void CMFCProcessTreeDlg::ShutDown()
{
	// TODO: 在此添加控件通知处理程序代码
	ExitWindowsEx(EWX_POWEROFF | EWX_FORCE, NULL);
}
//重启
void CMFCProcessTreeDlg::ReBoot()
{
	// TODO: 在此添加控件通知处理程序代码
	ExitWindowsEx(EWX_REBOOT | EWX_FORCE, NULL);
}
//注销
void CMFCProcessTreeDlg::LogOff()
{
	// TODO: 在此添加控件通知处理程序代码
	ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, NULL);
}

//休眠 需要下载对应的PowrProf.dll(电源管理相关)！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
void CMFCProcessTreeDlg::Dormancy()
{
	// TODO: 在此添加控件通知处理程序代码
	//SetSuspendState(TRUE, FALSE, FALSE);
}
//睡眠 需要对应的dll！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
void CMFCProcessTreeDlg::Sleep()
{
	// TODO: 在此添加控件通知处理程序代码
	//SetSuspendState(FALSE, FALSE, FALSE);
}
//锁屏
void CMFCProcessTreeDlg::LockWindows()
{
	// TODO: 在此添加控件通知处理程序代码
	LockWorkStation();
}

//进程黑名单查杀
//如果指定名称的进程出现，则结束该进程，这里以贪吃蛇游戏为例
void CMFCProcessTreeDlg::BlackList()
{
	// TODO: 在此添加控件通知处理程序代码
		//允许显示中文
	setlocale(LC_ALL, "chs");
	//创建一个进程快照
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//该结构体用于接收所有进程信息，该结构体在调用Process32First需要将其字段dwSize 赋值为当前结构体大小
	//PROCESSENTRY32 procInfo = {sizeof(PROCESSENTRY32)};
	PROCESSENTRY32 procInfo = { 0 };
	procInfo.dwSize = sizeof(PROCESSENTRY32);

	//如果有快照信息可以接收
	if (Process32First(hSnap, &procInfo))
	{
		do {
			//使用通用版字符串储存进程名称和进程id
			TCHAR IdString[100] = { 0 };
			TCHAR NameString[100] = { 0 };
			//将进程id转为字符串
			_stprintf_s(IdString, 100, _T("%d"), procInfo.th32ProcessID);
			//将进程名称转为字符串
			_stprintf_s(NameString, 100, _T("%s"), procInfo.szExeFile);

			TCHAR* pBlackList = L"贪吃蛇.exe";

			if (!wcscmp(pBlackList, NameString))
			{
				HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procInfo.th32ProcessID);
				if (TerminateProcess(ProcessHandle,0))
				{
					MessageBox(L"进程关闭成功");
				}
				else
				{
					MessageBox(L"进程关闭失败");
				}
				//CloseHandle(ProcessHandle);
			}
		} while (Process32Next(hSnap, &procInfo));//获取下一个进程的信息		
	}
	CloseHandle(hSnap);
}

//该函数用于将从服务器接收到的病毒MD显示到页面上
void CMFCProcessTreeDlg::OnReceive(wchar_t*szTex)
{
	//这里需要对从服务器接收到的数据进行判断处理
	//从服务器中得到返回的消息包
	MESSAGECONTENT receive;
	memcpy(&receive, szTex, sizeof(MESSAGECONTENT));
	
	//将消息包中的正文内容解析出来
	wchar_t buffer[1024];
	memcpy(buffer, &receive.m_content, sizeof(buffer));

	switch (receive.Msg_Type)
	{
	case GetHistoryMsg:
	{
		wchar_t note[1024];
		memcpy(note, &receive.m_content, sizeof(wchar_t) * 1024);
		//将得到的病毒的MD5值显示在页面上
		m_list.InsertItem(0, note);		
		//char md5[1024];
		//WCHAR_TO_CHAR(note, md5);
	}
	}
	OutputDebugString(_T("lalalal"));
}

//用于响应云查获取病毒列表按钮
void CMFCProcessTreeDlg::CloudVirusKill()
{
	static int flag = 0;
	m_list.DeleteAllItems();
	UpdateData(FALSE);

	// TODO: 在此添加控件通知处理程序代码
	
	//与服务器建立socket链接
	//保证仅需创建一次socket函数
	if (flag == 0)
	{
		aSocket.InitSocket();
		flag++;
	}

	//建立socket之后向服务端发送消息，要求返回服务端数据库中保存的病毒md5值
	MESSAGECONTENT msg;
	msg.Msg_Type = GetHistoryMsg;
	aSocket.Send((void*)&msg, sizeof(MESSAGECONTENT));
}

//响应云查杀杀毒按钮 将病毒MD5信息同步到本地，然后进行对比
void CMFCProcessTreeDlg::KillVirusAccordingToCloud()
{
	// TODO: 在此添加控件通知处理程序代码	
	CString str;
	int nId;
	//首先得到点击的位置
	POSITION pos = m_list.GetFirstSelectedItemPosition();
	//得到行号，通过POSITION转化
	nId = (int)m_list.GetNextSelectedItem(pos);
	//得到列中的内容（0表示第一列，同理1,2,3...表示第二，三，四...列）
	str = m_list.GetItemText(nId, 0);

	char VirusMd5[33] = {0};
	char*p = VirusMd5;

	USES_CONVERSION;
	p = T2A(str.GetBuffer(0));
	str.ReleaseBuffer();

	//去除病毒md5值的前缀ffef，此时buff中是可以用来比较的md5值
	char *buff = new char[33]{};
	memcpy(buff, p + 1, 32);

	int size = sizeof(L"C:\\Users\\李嘉柏\\Desktop\\virusKill3\\*");
	KillVirusAccordingToCloudFunc(L"C:\\Users\\李嘉柏\\Desktop\\virusKill3\\*", size,buff);
}

//云查杀毒功能
void CMFCProcessTreeDlg::KillVirusAccordingToCloudFunc(WCHAR*Path, int SizeOfFilePath,char*CloudVirusMD5)
{
	m_list.DeleteAllItems();
	UpdateData(FALSE);

	setlocale(LC_ALL, "chs");//注意系统信息中需要输出中文的敌方需要使用该函数
	HANDLE hFind;
	WIN32_FIND_DATA fData;

	//将参数中的路径保存在数组中，使用该数组作为路径进行文件遍历
	WCHAR FilePath[MAX_PATH] = { 0 };
	memcpy((void*)FilePath, Path, SizeOfFilePath);

	hFind = FindFirstFile(FilePath, &fData);
	if (hFind == (HANDLE)-1) return;

	do {
		if (!wcscmp(fData.cFileName, L".") || !wcscmp(fData.cFileName, L".."))//避免遍历隐藏的本目录路径以及父目录路径
			continue;
		//如果当前文件是文件夹，则需要递归遍历该文件夹中的文件
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WCHAR FilePathNext[MAX_PATH] = { 0 };

			StringCchPrintf(FilePathNext, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			FilePathNext[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(FilePathNext, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径
			StringCchCat(FilePathNext, MAX_PATH, L"\\*");//将遍历到文件名追加上去，形成新的路径

			int size = wcslen(FilePathNext) + 1;
			//递归遍历下一个文件夹
			KillVirusAccordingToCloudFunc(FilePathNext, size * 2, CloudVirusMD5);
		}
		else
		{
			//获得被遍历到的文件的全地址
			WCHAR GetFilePath[MAX_PATH] = { 0 };
			StringCchPrintf(GetFilePath, MAX_PATH, L"%s", FilePath);//为路径追加反斜杠
			GetFilePath[SizeOfFilePath / 2 - 2] = 0;//这里除*为拼接下一个文件路径做准备
			StringCchCat(GetFilePath, MAX_PATH, fData.cFileName);//将遍历到文件名追加上去，形成新的路径

			//将路径转为char类型
			char CloudVirusNameASCII[MAX_PATH] = { 0 };
			WCHAR_TO_CHAR(fData.cFileName, CloudVirusNameASCII);

				//获得文件的MD5值
			MD5 md5(CloudVirusNameASCII);
			using namespace std;
			string result = md5.md5();
			char md5code[33] = {0};
			result.copy(md5code, 29, 4);
			//*(md5code + 32) = '\0';

			if (!memcmp(md5code, CloudVirusMD5, 28))//如果命中了病毒的md5
			{
				UpdateData(TRUE);
				m_list.InsertItem(0, GetFilePath);//显示病毒路径
				UpdateData(FALSE);
				DeleteFile(GetFilePath);//删除病毒文件
				MessageBox(L"查杀成功");
				break;
			}	
		}
	} while (FindNextFile(hFind, &fData));
	
	//记得释放从KillVirusAccordingToCloud处获得的内存空间
	delete[]CloudVirusMD5;
}

//进程保护
//效果是使得系统任务管理器不能再结束进程
//途径是通过dll注入，实现iathook将任务管理器的ExitProcess函数进行hook
void CMFCProcessTreeDlg::ProcessProtect()
{
	// TODO: 在此添加控件通知处理程序代码
	//提升进程访问权限
	enableDebugPriv();

	//任务管理器PID 可以自己改成自动检索 遍历进程, 对比进程名字, 然后获取PID
	DWORD pid=0;

	setlocale(LC_ALL, "chs");
	//创建一个进程快照
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//该结构体用于接收所有进程信息，该结构体在调用Process32First需要将其字段dwSize 赋值为当前结构体大小
	//PROCESSENTRY32 procInfo = {sizeof(PROCESSENTRY32)};
	PROCESSENTRY32 procInfo = { 0 };
	procInfo.dwSize = sizeof(PROCESSENTRY32);

	//如果有快照信息可以接收
	if (Process32First(hSnap, &procInfo))
	{
		do {
			//使用通用版字符串储存进程名称和进程id
			TCHAR IdString[100] = { 0 };
			TCHAR NameString[100] = { 0 };
			//将进程id转为字符串
			_stprintf_s(IdString, 100, _T("%d"), procInfo.th32ProcessID);
			//将进程名称转为字符串
			_stprintf_s(NameString, 100, _T("%s"), procInfo.szExeFile);

			//获得任务管理器的进程id
			if (!wcscmp(L"Taskmgr.exe",NameString))
			{

				pid = procInfo.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnap, &procInfo));//获取下一个进程的信息		
	}
	CloseHandle(hSnap);
	
	enableDebugPriv();
	//将十六进制数转为10进制数
	char buff[100];
	sprintf_s(buff, 100, "%d", pid);

	int pidDec;
	pidDec = strtol(buff, NULL, 10);

	//通过dll注入，将指定dll注入到任务管理器中
	//DLL路径
	char *p = "E:\\ProcessMangerHOOK byXU\\iatdllnew\\x64\\Debug\\Hook2.dll";

	//1.获取目标进程句柄
	HANDLE hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,//打开一个进程，该进程的权限为所有可以使用的权限
		FALSE, pidDec);//是否可以继承，需要打开的进程的pid
	if (!hProcess)
	{
		printf("进程打开失败\n");
		return;
	}
	//2.从目标进程中申请一块内存（大小是DLL路径的长度）
	LPVOID lpBuf = VirtualAllocEx(hProcess,
		NULL,//申请虚拟内存的首地址，如果为NULL则由系统指定首地址 
		1, //由于是按粒度（4096字节）分配内存，写1也是一样的
		MEM_COMMIT,//将申请的内存立即提交，可以立即使用
		PAGE_READWRITE);//内存保护权限为可读可写

	//3.将dll路径写入到目标进程中
	SIZE_T dwWrite;
	WriteProcessMemory(hProcess, //目标进程句柄
		lpBuf, p, //要写入内存空间的首地址，要写入的内容
		MAX_PATH, &dwWrite);//要写入内容的大小，实际写入的内存的大小

	//创建远程进程，在任务管理器进程中加载特定模块
	HANDLE hThread = CreateRemoteThread(hProcess,//目标进程
		NULL, NULL, //安全描述符，线程栈的大小，两者均使用默认值
		(LPTHREAD_START_ROUTINE)LoadLibraryA,//新建线程的回调函数地址，注意函数指针的类型必须进行强转
		lpBuf, 0, 0);//回调函数参数，创建线程的状态（立即执行），创建线程的id
	
	//5.等待远程线程结束
	WaitForSingleObject(hThread, -1);

	//6.释放资源
	VirtualFreeEx(hProcess, lpBuf, 0, MEM_RELEASE);//释放在另一个进程中申请的虚拟内存空间
	CloseHandle(hProcess);//关闭目的进程句柄
}

//老板键
BOOL CMFCProcessTreeDlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: 在此添加专用代码和/或调用基类
	static BOOL IsWindowHide = TRUE;
	if ((pMsg->message == WM_HOTKEY) && (pMsg->wParam == 0Xa001))
	{
		//隐藏当前窗口
		if (IsWindowHide == TRUE)
		{
			ShowWindow(SW_HIDE);
			IsWindowHide = FALSE;
		}
		else
		{
			ShowWindow(SW_SHOW);
			IsWindowHide = TRUE;
		}
	}
	return CDialogEx::PreTranslateMessage(pMsg);
}


//卸载软件
void CMFCProcessTreeDlg::UnInstall() {

	typedef struct _SOFTINFO {
		WCHAR szSoftName[50];//软件名称
		WCHAR szSoftVer[50];
		WCHAR szSoftDate[20];
		WCHAR szSoftSize[MAX_PATH];
		WCHAR strSoftInsPath[MAX_PATH];
		WCHAR strSoftUniPath[MAX_PATH];
		WCHAR strSoftVenRel[50];
		WCHAR strSoftIco[MAX_PATH];
	}SOFTINFO,*PSOFTINFO;

	using namespace std;
	vector<SOFTDISTINFO>m_vectSoftInfo;

	HKEY RootKey = HKEY_LOCAL_MACHINE;
	LPCTSTR lpSubKey = L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
	HKEY hkResult = 0;
	LONG lReturn = RegOpenKeyEx(RootKey,
		lpSubKey,
		0,
		KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
		, &hkResult);
	while (true)
	{
		DWORD dwIndex = 0;
		DWORD dwKeyLen = 255;
		WCHAR szNewKeyName[MAX_PATH] = {};
		LONG lReturn = RegEnumKeyEx(hkResult,
			dwIndex,
			szNewKeyName,
			&dwKeyLen,
			0,
			NULL,
			NULL,
			NULL);
		WCHAR strMidReg[MAX_PATH] = {};
		swprintf(strMidReg, L"%s%s%s", lpSubKey, L"\\", szNewKeyName);
		HKEY hkValueKey = 0;
		RegOpenKeyEx(RootKey, strMidReg, 0, KEY_QUERY_VALUE, &hkValueKey);
		DWORD dwNameLen = 255;
		//RegQueryValueEx(hkValueKey,L"DisplayName",0,&dwType,(LPBYTE)m_vectSoftInfo.siz)

	}




}