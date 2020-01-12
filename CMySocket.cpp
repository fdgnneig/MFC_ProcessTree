//#include "stdafx.h"
//#include "CMySocket.h"
//
//
//CMySocket::CMySocket()
//{
//}
//
//
//CMySocket::~CMySocket()
//{
//}

#include "stdafx.h"
#include "CMySocket.h"
#include "MFC_ProcessTreeDlg.h"

CMySocket::CMySocket()
{
}
CMySocket::~CMySocket()
{
}

//void CMySocket:: OnReceive() {
//	//这里规定了一次发送的数据最多不能超过2048个字节
//	wchar_t s[1024] = { 0 };
//	//接收消息
//	Receive(s, sizeof(s));
//	CChatRoomclientDlg *p = (CChatRoomclientDlg*)AfxGetMainWnd();
//	p->OnReceive(s);
//	//CSocket::OnReceive(nErrorCode);
//}


void CMySocket::InitSocket() {
	//初始化
	AfxSocketInit();
	//创建socket
	this->Create();
	//连接指定的地址和端口
	this->Connect(L"127.0.0.1", 12345);
}


void CMySocket::OnReceive(int nErrorCode)
{
	// TODO: 在此添加专用代码和/或调用基类

	//这里规定了一次发送的数据最多不能超过2048个字节	
	wchar_t s[1100] = { 0 };
	//接收消息
	Receive(s, sizeof(s));

	CMFCProcessTreeDlg *p = (CMFCProcessTreeDlg*)AfxGetMainWnd();
	
	p->OnReceive(s);
	//CSocket::OnReceive(nErrorCode);

	CSocket::OnReceive(nErrorCode);
}
