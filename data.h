#pragma once
#pragma once
#include <windows.h>
//主窗口需要响应的自定义消息
enum UserMessage {
	WM_REGISTER = WM_USER + 1,//注册消息
	WM_CHATMESSAGE,
	WM_CHATMESSAGEtoChatBox,
	WM_FINDUSER,//获得用户名的消息
	WM_FINDUSERtoChatBox,

	WM_CHATTOONE,//私聊
	WM_CHATTOONEtoChatBox,//私聊返回结果

	WM_HISTORYMSG,//获得聊天记录的功能
	WM_HISTORYMSGtoChatBox,
	WM_FRIEND,//加好友
	WM_SHOWFRIEND//显示好友
};

typedef enum MessageType {
	RegisterMessage,//注册消息0
	LoginMessage,//1
	ChatMessage,//2
	FindUser,//3
	GetHistoryMsg,//4
	ChatOne,//5
	Friend,//6
	ShowFriendinfo//7

}MsgType;

//登陆正文

//私聊正文

//注册正文
typedef struct REGISTER {
	//用户名和密码长度限制为20字节，实际数据库允许存储50字节的信息
	int namelen;
	int passlen;
	wchar_t user_name[20];
	wchar_t user_pass[20];
	//这里性别为女，即值为0 性别为男，则为1
	int user_sex;
}REMSG;


typedef struct LONGIN {
	//用户名和密码长度限制为20字节，实际数据库允许存储50字节的信息
	int namelen;
	int passlen;
	wchar_t user_name[20];
	wchar_t user_pass[20];
}LOMSG;


typedef struct FRIEND {
	//用户名和密码长度限制为20字节，实际数据库允许存储50字节的信息
	int namelen1;
	int namelen2;
	wchar_t user_name1[20];
	wchar_t user_name2[20];
}FRIENT;

//群聊消息内容
typedef struct MESSAGECONTENT
{
	MsgType Msg_Type;//消息类型
	HWND hwnd;//窗口句柄
	DWORD dwMsgLen;//消息正文长度
	union MyUnion//消息正文
	{
		wchar_t buff[1024];//当消息为其他消息
		//登陆信息
		LOMSG lomsg;
		//注册信息
		REMSG remsg;
		//加好友消息
		FRIEND femsg;
	}m_content;
};

//私聊消息内容
typedef struct TOONE
{
	MsgType Msg_Type;//消息类型
	wchar_t anotherPerson[10];//私聊对手的用户名你
	DWORD dwMsgLen;//消息正文长度
	union MyUnion//消息正文
	{
		wchar_t buff[1024];//当消息为其他消息
		//登陆信息
		LOMSG lomsg;
		//注册信息
		REMSG remsg;
	}m_content;
};


//将句柄作为全局变量保存，而可以实现直接向某个窗口发消息的功能，暂时不用
//extern HWND Dlglog_hWnd;

extern HWND g_ChatHandle;
extern HWND g_LogHandle;