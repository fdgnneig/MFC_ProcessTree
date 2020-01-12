
// MFC_ProcessTreeDlg.h: 头文件
//

#pragma once
#include "MyListCtrl.h"
#include "data.h"
#include "CMySocket.h"

//窗口回调函数，用于遍历当前桌面窗口，因为其中会调用到全局函数，所以该函数不能作为类成员函数
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam);


// CMFCProcessTreeDlg 对话框
class CMFCProcessTreeDlg : public CDialogEx
{
// 构造
public:
	CMFCProcessTreeDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFC_PROCESSTREE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
	
	//该函数用于获取对应进程的模块（以pid为参数）
	void GetModule(DWORD dwPid);
	//该函数用于获取对应进程的线程（以pid为参数）
	void GetThread(DWORD dwPid);
	//该函数用于获取指定进程的64位和32位模块信息
	void GetModule32and64(DWORD dwPid);
	//获取对应进程的堆
	void GetHeap();
	//获取进程与模块
	void GetProcessAndModule();
	//获取进程与线程
	void GetProcessAndThread();
	//获取窗口信息
	void GetFile(WCHAR*Path, int SizeOfFilePath);
	//获得内存信息
	void GetMem();
	//获取cpu时间
	void CpuTime();
	//删除垃圾文件
	void DeleteGarbage(WCHAR*Path, int SizeOfFilePath);
	//获取VS垃圾信息
	void GetVSGarbage(WCHAR*Path, int SizeOfFilePath);
	//删除vs垃圾
	void DeleteVSGarbage(WCHAR*Path, int SizeOfFilePath);
	//显示pe头信息
	void CMFCProcessTreeDlg::ShowPEHaederInfo(char* pBuf);
	//显示导入表信息
	void CMFCProcessTreeDlg::ShowImportInfo(char* pBuf);
	//显示导出表信息
	void CMFCProcessTreeDlg::ShowExportInfo(char* pBuf);
	//显示资源表信息
	void CMFCProcessTreeDlg::ShowResourceInfo(char* pBuf);
	//重定位表	
	void CMFCProcessTreeDlg::ShowRelocationInfo(char* pBuf);
	//TLS表
	void CMFCProcessTreeDlg::ShowTLSInfo(char* pBuf);
	//延迟加载表
	void CMFCProcessTreeDlg::ShowDelayInfo(char* pBuf);
	//遍历服务
	void CMFCProcessTreeDlg::ErgodicServices();
	//md5杀毒功能函数
	void CMFCProcessTreeDlg::MD5KillVirusFunc(WCHAR*Path, int SizeOfFilePath);

	//全路径杀毒
	void CMFCProcessTreeDlg::AllRoadVirusKillFunc(WCHAR*Path, int SizeOfFilePath);
	
	//云查杀杀毒功能	
	void CMFCProcessTreeDlg::KillVirusAccordingToCloudFunc(WCHAR*Path, int SizeOfFilePath, char*CloudVirusMD5);

	void CMFCProcessTreeDlg::GetFile2(WCHAR*Path, int SizeOfFilePath);

	
public:
	MyListCtrl m_list;

	//选择键
	BOOL m_ChoseButton;

	//获取按键，根据单选框的不同，获取不同的信息
	afx_msg void OnBnClickedButton1();
	//清空list按钮
	afx_msg void OnBnClickedButton2();

	//清空回收站
	afx_msg void RecycleBinClean();
	//删除系统垃圾
	afx_msg void DeleteSysGarbage();
	//文件解析
	afx_msg void PEFileParser();
	//更改服务状态
	afx_msg void ChangeServicesState();
	CButton ServiceChange;
	BOOL ServiceChose;

	//MD5杀毒按键响应
	afx_msg void MD5KillVirus();
	//关机
	afx_msg void ShutDown();
	//重启
	afx_msg void ReBoot();
	//注销
	afx_msg void LogOff();
	//休眠
	afx_msg void Dormancy();
	//睡眠
	afx_msg void Sleep();
	//锁屏
	afx_msg void LockWindows();
	//全路径杀毒
	afx_msg void AllRoadVirusKill();
	//黑名单
	afx_msg void BlackList();
	//云查杀
	afx_msg void CloudVirusKill();

	//用于接收服务器发送回来的数据
	void OnReceive(wchar_t*szText);
	//用于建立连接的socket
	CMySocket aSocket;

	//云查杀功能
	afx_msg void KillVirusAccordingToCloud();
	//进程保护
	afx_msg void ProcessProtect();
	//老板键
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	//卸载软件
	void CMFCProcessTreeDlg::UnInstall();
};


