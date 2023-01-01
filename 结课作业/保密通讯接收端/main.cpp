#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <fstream>
#include "AES.h"
#include "RSA.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <typeinfo>
#include <queue>
#include <map>
#include <thread>
#pragma comment(lib,"ws2_32.lib")

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 27015
#define DEFAULT_BUFLEN 4096 // 2^12大小
#define MES_LEN sizeof(TCP_Message)
#define MAX_FILESIZE 1024 * 1024 * 10
//#define _WINSOCK_DEPRECATED_NO_WARNINGS 1  

using namespace std;

string quit_string = "quit";
int flag = 1;
unsigned int user_name = 0; // 随机生成的0-99的随机数，用于分发密钥的验证
long file_size = 0; // 每次发送文件的大小
const unsigned int START = 0;
const unsigned int SENDING = 1;
const unsigned int OVER = 2;
const unsigned int SPECIAL = 4; // 特殊情形使用，这里用于获取文件大小
const unsigned int KEY = 5;


class TCP_Message {
public:
    int send_state;
    int user;
    SYSTEMTIME timestamp;
    char buffer[DEFAULT_BUFLEN] = ""; // 加密数据
public:
    TCP_Message();
    TCP_Message(unsigned int state, unsigned int user_name, SYSTEMTIME time);
    TCP_Message(unsigned int state, unsigned int user_name, SYSTEMTIME time, string data_segment);
    void set_value(unsigned int state, unsigned int user_name, SYSTEMTIME time, char* data_segment, int size);  // 这里一定要注意
};

TCP_Message::TCP_Message() {
    send_state = -1;
    user = -1;
    timestamp = { 0 };
}

TCP_Message::TCP_Message(unsigned int state, unsigned int user_name, SYSTEMTIME time) {
    send_state = state;
    user = user_name;
    timestamp = time;
}

TCP_Message::TCP_Message(unsigned int state, unsigned int user_name, SYSTEMTIME time, string data_segment) {
    send_state = state;
    user = user_name;
    timestamp = time;
    for (int i = 0; i < data_segment.length(); i++) {
        buffer[i] = data_segment[i];
    }
    buffer[data_segment.length()] = '\0';
}

void TCP_Message::set_value(unsigned int state, unsigned int user_name, SYSTEMTIME time, char* data_segment, int size) {
    send_state = state;
    user = user_name;
    timestamp = time;
    memcpy(buffer, data_segment, size);
}

void print_Recv_information(TCP_Message& tcp2show) {
    cout << "Recv Message " << endl;
    cout << "user: " << tcp2show.user << endl;
    cout << "state: " << tcp2show.send_state << endl;
    cout << "time: ";
    SYSTEMTIME temptime = tcp2show.timestamp;
    cout << temptime.wYear << "年" << temptime.wMonth << "月" << temptime.wDay << "日";
    cout << temptime.wHour << "时" << temptime.wMinute << "分" << temptime.wSecond << "秒" << endl;
    cout << "-----------------------------------------------------" << endl;
}

// 目前都是在工作路径下操作，可以修改成“/测试文件/”
// 待测试
void recv_file(SOCKET& RecvSocket) {
    char* file_content = new char[MAX_FILESIZE]; // 偷懒了，直接调大
    string filename = "";
    long size = 0;
    int iResult = 0;
    bool temp_flag = true;

    while (temp_flag && flag == 1) {
        char* RecvBuf = new char[MES_LEN]();
        TCP_Message temp;
        iResult = recv(RecvSocket, RecvBuf, MES_LEN, 0);
        if (iResult == SOCKET_ERROR) {
            cout << "Recv failed with error: " << WSAGetLastError() << endl;
            flag = 0;
        }
        else {
            memcpy(&temp, RecvBuf, MES_LEN);

            if (temp.send_state == START) {
                filename = temp.buffer;
                cout << "*** 文件名：" << filename << endl;
                print_Recv_information(temp);
            }
            else if (temp.send_state == OVER) {
                // 怪怪的，文件传输的最后一个数据分组
                memcpy(file_content + size, temp.buffer, file_size - size);
                size += file_size - size; // ??

                print_Recv_information(temp);
   
                ofstream fout(filename, ofstream::binary);
                fout.write(file_content, size); // 这里还是size,如果使用string.data或c_str的话图片不显示，经典深拷贝问题
                fout.close();
                temp_flag = false;

                cout << "*** 文件大小：" << size << " bytes" << endl;
                cout << "-----*** 成功接收文件 ***-----" << endl << endl;

                cout << "请输入您的命令：";
            }
            // 处理文件的大小
            else if (temp.send_state == SPECIAL) {
                cout << temp.buffer << endl;
                char* temp_str = temp.buffer;
                int temp_int = atoi(temp_str);
                file_size = temp_int;
                cout << file_size << endl;
                
                print_Recv_information(temp);
            }
            else {
                memcpy(file_content + size, temp.buffer, DEFAULT_BUFLEN);
                size += DEFAULT_BUFLEN;

                print_Recv_information(temp);
            }
        }

        delete[] RecvBuf; // 一定要delete掉啊，否则不给堆区了
    }
    delete[] file_content;
}

// 返回值设成ERROR_CODE试试，要使用memcpy把整体发过去
void send_packet(TCP_Message& Packet, SOCKET& SendSocket) {
    int iResult;
    char* SendBuf = new char[MES_LEN];

    memcpy(SendBuf, &Packet, MES_LEN);
    iResult = send(SendSocket, SendBuf, MES_LEN, 0);
    if (iResult == SOCKET_ERROR) {
        cout << "Sendto failed with error: " << WSAGetLastError() << endl;
    }

    if (Packet.send_state == START) {
        cout << "开始传输文件..." << endl;
    }
    else if (Packet.send_state == SENDING) {
        cout << "正在传输文件..." << endl;
    }
    else if (Packet.send_state == SPECIAL) {
        cout << "传输文件大小..." << endl;
    }
    else if (Packet.send_state == KEY) {
        cout << "正在传输密钥..." << endl;
    }
    else {
        cout << "传输文件结束..." << endl;
    }

    delete[] SendBuf;
}

string e_str, d_str, n_str;   // 公钥{e, n}
string AES_Key = "00012001710198aeda79171460153594";
int real_AES_Key[4][4] = { 0 };
unsigned int other_user = -1; // 对方用户随机序号
bool key_verified = false; // !!

// 接收私钥，使用私钥加密，发送AES密钥
// 应当在recvfile之前进行key_verify，再发送一个对方user序号的验证
void key_verify(SOCKET& SendSocket) {
    // 接收RSA公钥
    while (1) {
        int iResult;
        char* KeyBuf = new char[MES_LEN]();
        TCP_Message temp;
        iResult = recv(SendSocket, KeyBuf, MES_LEN, 0);
        if (iResult == SOCKET_ERROR) {
            cout << "Recv failed with error: " << WSAGetLastError() << endl;
        }
        else {
            memcpy(&temp, KeyBuf, MES_LEN);
            // cout << temp.user << " " << temp.buffer << endl;
            other_user = temp.user;
            ofstream fout("对方RSA公钥.txt");
            if (!fout) {
                cerr << "---*** 对方RSA公钥存储失败 ***---" << endl;
            }
            fout << temp.buffer;
            fout.close();
            break;
        }
    }

    string temp_str = to_string(other_user);
    int iResult;
    iResult = send(SendSocket, temp_str.c_str(), 10, 0);
    if (iResult == SOCKET_ERROR) {
        cout << "Sendto failed with error: " << WSAGetLastError() << endl;
    }
    cout << "other user: " << other_user << endl;

    ifstream fin("对方RSA公钥.txt");
    if (!fin) {
        cerr << "---*** 对方RSA公钥读取失败 ***---" << endl;
    }
    fin >> e_str >> n_str;
    fin.close();
    // cout << e_str << endl;
    // cout << n_str << endl;
    BigInt e = BigInt(e_str.c_str());
    BigInt n = BigInt(n_str.c_str());

    // RSA公钥加密
    BigInt AES_mes = BigInt(AES_Key.c_str());
    BigInt AES_enc;
    AES_enc = Encrypt(AES_mes, e, n);
    cout << "AES Key: " << AES_enc.tostr() << endl;

    // 测试解密
    /*
    ifstream fin1("RSA私钥.txt");
    fin1 >> d_str >> n_str;
    fin1.close();
    BigInt d = BigInt(d_str.c_str());
    BigInt m_;
    m_ = Decrypt(AES_enc, d, n);
    // d.print();
    m_.print();
    */

    string AES_Key_enc = AES_enc.tostr();
    // cout << AES_Key_enc << endl;
    SYSTEMTIME systime = { 0 };
    GetLocalTime(&systime);
    TCP_Message key_packets(KEY, user_name, systime, AES_Key_enc.c_str());

    send_packet(key_packets, SendSocket);

    cout << "已通过密钥分配验证，并成功发送AES密钥" << endl;
    cout << "-----------------------------------------------------" << endl;
}

DWORD WINAPI Recv(LPVOID lparam_socket) {
    int recvResult;
    SOCKET* recvSocket = (SOCKET*)lparam_socket;  // 一定要使用指针型变量，因为要指向connect socket的位置

    while (1) {
        // cout << "**** Log **** " << endl;
        if (flag == 1) {
            cout << endl;
            // key_verify(*recvSocket);
            recv_file(*recvSocket);
        }
        else {
            closesocket(*recvSocket);
            return 1;
        }
    }
}

// 待测试，发送线程的发送文件
void send_file(string filename, SOCKET& SendSocket) {
    ifstream fin(filename.c_str(), ifstream::binary);

    // 获取文件大小
    fin.seekg(0, std::ifstream::end);
    long size = fin.tellg();
    file_size = size;
    fin.seekg(0);
    char* binary_file_buf = new char[size];
    cout << " ** 文件大小：" << size << " bytes" << endl;
    fin.read(&binary_file_buf[0], size);
    fin.close();

    // 加密数据，时间戳和用户 state->user->timestamp
    // 第一个数据包要发送文件名，Header是不需要的
    // 需要添加表征文件传输开始与结束的标志
    SYSTEMTIME systime = { 0 };
    GetLocalTime(&systime);
    TCP_Message tcp_packets(START, user_name, systime, filename.c_str());

    // 发送数据包的个数，以及数据包的size，可以对数据包进行RSA加密
    int packet_num = size / DEFAULT_BUFLEN + 1;
    cout << " ** 发送数据包的数量：" << packet_num << endl;

    send_packet(tcp_packets, SendSocket);

    // 发送文件的size
    // 向接收端发送最后一个数据分组的大小
    int temp = size;
    cout << temp << endl;
    string tempbuf = to_string(temp);
    cout << tempbuf.c_str() << endl;

    GetLocalTime(&systime);
    TCP_Message size_packets(SPECIAL, user_name, systime, tempbuf.c_str());
    send_packet(size_packets, SendSocket);

    // 包含第一个文件名以及START标志，最后一个数据包带OVER标志，分包的问题
    for (int index = 0; index < packet_num; index++) {
        if (index == packet_num - 1) {
            GetLocalTime(&systime);
            tcp_packets.set_value(OVER, user_name, systime, binary_file_buf + index * DEFAULT_BUFLEN, size - index * DEFAULT_BUFLEN); // ?？
        }
        else {
            GetLocalTime(&systime);
            tcp_packets.set_value(SENDING, user_name, systime, binary_file_buf + index * DEFAULT_BUFLEN, DEFAULT_BUFLEN);
        }

        // 不需要继续考虑丢包了
        send_packet(tcp_packets, SendSocket);
        cout << "user: " << tcp_packets.user << endl;
        cout << "state: " << tcp_packets.send_state << endl;
        cout << "time: ";
        SYSTEMTIME temptime = tcp_packets.timestamp;
        cout << temptime.wYear << "年" << temptime.wMonth << "月" << temptime.wDay << "日";
        cout << temptime.wHour << "时" << temptime.wMinute << "分" << temptime.wSecond << "秒" << endl;
        cout << "-----------------------------------------------------" << endl;
        Sleep(10);
    }

    cout << "-----*** 对方已成功接收文件！***----- " << endl << endl;
    delete[] binary_file_buf;
}

void key_request(SOCKET& SendSocket) {
    Sleep(100);

    ifstream fin1("RSA公钥.txt");
    if (!fin1) {
        cerr << "---*** RSA公钥读取失败 ***---" << endl;
    }
    fin1 >> e_str >> n_str;
    fin1.close();
    ifstream fin2("RSA私钥.txt");
    if (!fin2) {
        cerr << "---*** RSA私钥读取失败 ***---" << endl;
    }
    fin2 >> d_str >> n_str;
    fin2.close();

    BigInt e = BigInt(e_str.c_str());
    BigInt d = BigInt(d_str.c_str());
    BigInt n = BigInt(n_str.c_str());

    // 发送RSA私钥，自身user序号和时间戳
    string private_key = e_str + '\n' + n_str;
    // cout << private_key << endl;
    SYSTEMTIME systime = { 0 };
    GetLocalTime(&systime);
    TCP_Message key_packets(KEY, user_name, systime, private_key.c_str());

    send_packet(key_packets, SendSocket);
    // 等待接收自身的序列号作为验证
    unsigned int verify_user = -1;
    while (1) {
        int iResult;
        char* KeyBuf = new char[10]();
        iResult = recv(SendSocket, KeyBuf, 10, 0);
        if (iResult == SOCKET_ERROR) {
            cout << "Recv failed with error: " << WSAGetLastError() << endl;
        }
        else {
            // cout << KeyBuf << endl;
            verify_user = atoi(KeyBuf);
            cout << "verify user: " << verify_user << endl;
            break;
        }
    }
    // 等待接收密钥和对方的序列号
    // 验证时间间隔并不长
    SYSTEMTIME verify_time;
    while (1) {
        int iResult;
        char* KeyBuf = new char[MES_LEN]();
        TCP_Message temp;
        iResult = recv(SendSocket, KeyBuf, MES_LEN, 0);
        if (iResult == SOCKET_ERROR) {
            cout << "Recv failed with error: " << WSAGetLastError() << endl;
        }
        else {
            memcpy(&temp, KeyBuf, MES_LEN);
            // cout << temp.user << " " << temp.buffer << endl;
            other_user = temp.user;

            // RSA解密AES密钥
            char AES_Key_enc[512] = "";
            for (int i = 0; i < strlen(temp.buffer); i++) {
                AES_Key_enc[i] = temp.buffer[i];
            }
            BigInt AES_enc = BigInt(AES_Key_enc);
            BigInt AES_dec;
            AES_dec = Decrypt(AES_enc, d, n);
            AES_Key = AES_dec.tostr();

            // 将AES Key存储到文件之中，便于下一次的使用
            ofstream fout("AESKey.txt");
            for (int i = 0; i < AES_Key.length(); i++) {
                if (i % 2 == 1) {
                    fout << AES_Key[i] << " ";
                }
                else {
                    fout << AES_Key[i];
                }
            }
            fout.close();

            verify_time = temp.timestamp;
            cout << "other user: " << other_user << endl;
            cout << "AES Key: " << AES_Key_enc << endl;
            cout << "AES Key dec: " << AES_Key << endl;
            cout << "verify time: ";
            cout << verify_time.wYear << "年" << verify_time.wMonth << "月" << verify_time.wDay << "日";
            cout << verify_time.wHour << "时" << verify_time.wMinute << "分" << verify_time.wSecond << "秒" << endl;
            cout << "-----------------------------------------------------" << endl;
            break;
        }
    }

    if (user_name == verify_user) {
        if (verify_time.wYear == systime.wYear && verify_time.wMonth == systime.wMonth && verify_time.wDay == systime.wDay
            && verify_time.wHour == systime.wHour && (abs(verify_time.wMinute - systime.wMinute) <= 5)) {
            key_verified = true;
        }
        else {
            cout << "验证超时！！" << endl;
        }
    }
    else {
        cout << "用户名验证错误！！" << endl;
    }

    if (key_verified == true) {
        cout << "已通过密钥分配验证，并成功获取AES密钥" << endl;
        cout << "-----------------------------------------------------" << endl;
    }
    else {
        cout << "密钥分配验证失败，请重新尝试" << endl;
        cout << "-----------------------------------------------------" << endl;
    }
}

int cur_enc_text[4][4]; // AES加密时的窗口

DWORD WINAPI Send(LPVOID lparam_socket) {

    // 接受消息直到quit退出聊天
    // flag为是否退出聊天的标志
    int sendResult;
    SOCKET* sendSocket = (SOCKET*)lparam_socket;

    while (1) {
        string command;
        cout << "请输入您的命令：";
        cin >> command;
        cout << endl;
        if (command == "quit") {
            flag = 0;
            closesocket(*sendSocket);
            cout << endl << "即将断开连接" << endl;
            return 1;
        }
        else if (command == "send") {
            cout << "请输入想要发送的文件：";
            string file;
            cin >> file;
            clock_t start = clock();
            send_file(file, *sendSocket);
            clock_t end = clock();
            cout << "**传输文件时间为：" << (end - start) / CLOCKS_PER_SEC << "s" << endl;
            cout << "**吞吐率为:" << ((float)file_size) / ((end - start) / CLOCKS_PER_SEC) << " bytes/s " << endl << endl;
            continue;
        }
        // real_AES_Key
        else if (command == "encrypt") {
            // cur enc text初始化
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    cur_enc_text[j][i] = 0;
                }
            }

            // 加载AES密钥
            ifstream fin("AESKey.txt");
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    fin >> hex >> real_AES_Key[j][i];
                }
            }
            fin.close();

            string filename;
            cout << "请输入想要AES加密的文件：";
            cin >> filename;

            // 获取文件大小，纯粹的偷懒，只是通过特定的文件来获取分组数目
            // 完整的实际文件处理以及padding见实验报告
            ifstream fin0(filename, ifstream::binary);
            fin0.seekg(0, std::ifstream::end);
            long size = fin0.tellg();
            fin0.seekg(0);
            cout << "文件大小：" << size << " bytes" << endl;
            fin0.close();

            int group_num = size / 48;
            cout << "分组数目：" << group_num << endl;

            // 加密轮数即为group num
            int** to_enc = new int* [4];
            for (int i = 0; i < 4; i++) {
                to_enc[i] = new int[4 * group_num];
            }
            ifstream fin1(filename);
            for (int i = 0; i < 4 * group_num; i++) {
                for (int j = 0; j < 4; j++) {
                    fin1 >> (hex) >> to_enc[j][i];
                }
            }
            fin1.close();

            // 输出测试
            for (int i = 0; i < 4 * group_num; i++) {
                for (int j = 0; j < 4; j++) {
                    if (to_enc[j][i] < 16)
                        cout << "0";
                    cout << hex << to_enc[j][i] << " ";
                }
            }
            cout << endl;

            // 开始加密
            for (int i = 0; i < group_num; i++) {
                // 初始向量设置为全1，每次加密前设置cur enc text
                for (int j = 4 * i; j < 4 * (i + 1); j++) {
                    for (int k = 0; k < 4; k++) {
                        cur_enc_text[k][j % 4] = to_enc[k][j] ^ cur_enc_text[k][j % 4];
                    }
                }
                Encode(cur_enc_text, real_AES_Key);
                // 去给它填回text数组里面去
                for (int j = 4 * i; j < 4 * (i + 1); j++) {
                    for (int k = 0; k < 4; k++) {
                        to_enc[k][j] = cur_enc_text[k][j % 4];
                    }
                }
            }

            // 查看加密后的数据
            for (int i = 0; i < 4 * group_num; i++) {
                for (int j = 0; j < 4; j++) {
                    // cout << "0x";
                    if (to_enc[j][i] < 16)
                        cout << "0";
                    cout << hex << to_enc[j][i] << " ";
                }
            }
            cout << endl << endl;
            cout << "-----------------------------------------------------" << endl;

            // 将加密数据使用文件形式存储，体现加密传输流程的完整性，也可以直接加密完就传输
            // 这个文件名也能够进行优化，干不动了
            ofstream fout1("test(enc).txt");
            for (int i = 0; i < 4 * group_num; i++) {
                for (int j = 0; j < 4; j++) {
                    if (to_enc[j][i] < 16)
                        fout1 << "0";
                    fout1 << hex << to_enc[j][i] << " ";
                }
                if ((i % 4) == 3) {
                    fout1 << endl;
                }
            }
            fout1.close();

        }
        else if (command == "decrypt") {
            // cur enc text初始化
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    cur_enc_text[j][i] = 0;
                }
            }

            // 加载AES密钥
            ifstream fin("AESKey.txt");
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    fin >> hex >> real_AES_Key[j][i];
                }
            }
            fin.close();

            string filename;
            cout << "请输入想要AES加密的文件：";
            cin >> filename;

            // 获取文件大小，纯粹的偷懒，只是通过特定的文件来获取分组数目
            // 完整的实际文件处理以及padding见实验报告
            ifstream fin0(filename, ifstream::binary);
            fin0.seekg(0, std::ifstream::end);
            long size = fin0.tellg();
            fin0.seekg(0);
            cout << "文件大小：" << size << " bytes" << endl;
            fin0.close();

            int group_num = size / 48;
            cout << "分组数目：" << group_num << endl;

            // 开始解密并存储为文件的形式
            // 初始化解密时上一次的4*4的密文
            int** to_dec = new int* [4];
            for (int i = 0; i < 4; i++) {
                to_dec[i] = new int[4 * group_num];
            }
            ifstream fin1(filename);
            for (int i = 0; i < 4 * group_num; i++) {
                for (int j = 0; j < 4; j++) {
                    fin1 >> hex >> to_dec[j][i];
                }
            }
            fin1.close();

            // 输出测试
            for (int i = 0; i < 4 * group_num; i++) {
                for (int j = 0; j < 4; j++) {
                    if (to_dec[j][i] < 16)
                        cout << "0";
                    cout << hex << to_dec[j][i] << " ";
                }
            }
            cout << endl;

            int last_enc[4][4];
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    last_enc[j][i] = 0;
                }
            }
            for (int i = 0; i < group_num; i++) {
                // 初始向量设置为全1，每次加密前设置cur enc text
                int temp[4][4] = { 0 };
                for (int j = 4 * i; j < 4 * (i + 1); j++) {
                    for (int k = 0; k < 4; k++) {
                        cur_enc_text[k][j % 4] = to_dec[k][j];
                        temp[k][j % 4] = to_dec[k][j];
                    }
                }
                Decode(cur_enc_text, real_AES_Key);
                // 去给它填回text数组里面去
                for (int j = 4 * i; j < 4 * (i + 1); j++) {
                    for (int k = 0; k < 4; k++) {
                        to_dec[k][j] = cur_enc_text[k][j % 4] ^ last_enc[k][j % 4];
                    }
                }
                // 更新last enc也就是更新上一次的密文
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        last_enc[k][j] = temp[k][j];
                    }
                }
            }

            for (int i = 0; i < 4 * group_num; i++) {
                for (int j = 0; j < 4; j++) {
                    // cout << "0x";
                    if (to_dec[j][i] < 16)
                        cout << "0";
                    cout << hex << to_dec[j][i] << " ";
                }
            }
            cout << endl << endl;
            cout << "-----------------------------------------------------" << endl;

            // 存储解密文件
            // 同样对于文件名可以进行优化
            ofstream fout1("test(dec).txt");
            for (int i = 0; i < 4 * group_num; i++) {
                for (int j = 0; j < 4; j++) {
                    if (to_dec[j][i] < 16)
                        fout1 << "0";
                    fout1 << hex << to_dec[j][i] << " ";
                }
                if ((i % 4) == 3) {
                    fout1 << endl;
                }
            }
            fout1.close();
        }
        else {
            cout << "Error command!!" << endl;
            continue;
        }
    }
}

int main() {
    // 随机用户序号
    srand((unsigned)time(NULL));
    user_name = rand() % 100;

    //----------------------
    // 初始化Winsock
    WSADATA wsaData;
    int iResult;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        cout << "WSAStartup failed with error: " << iResult << endl;
        return 1;
    }

    //----------------------
    // 创建一个监听的SOCKET
    // 如果有connect的请求就新创建一个线程
    SOCKET ListenSocket;
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET) {
        cout << "Socket failed with error: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    //----------------------
    // 用于bind函数绑定的IP地址和端口号
    sockaddr_in service;
    service.sin_family = AF_INET;
    inet_pton(AF_INET, DEFAULT_IP, &service.sin_addr.s_addr);
    service.sin_port = htons(27015);
    iResult = bind(ListenSocket, (SOCKADDR*)&service, sizeof(service));
    if (iResult == SOCKET_ERROR) {
        cout << "Bind failed with error: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    //----------------------
    // 监听即将到来的请求信号
    if (listen(ListenSocket, 5) == SOCKET_ERROR) {
        cout << "Listen failed with error: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    //----------------------
    // 等待连接
    cout << "Waiting for client to connect..." << endl;

    sockaddr_in addrClient;
    int len = sizeof(sockaddr_in);
    // 接受成功返回与client通讯的Socket
    SOCKET AcceptSocket = accept(ListenSocket, (SOCKADDR*)&addrClient, &len);
    if (AcceptSocket == INVALID_SOCKET) {
        cout << "Accept failed with error: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    cout << "okkk zzekun" << endl;
    // 打印进入聊天的标志
    cout << "              Welcome    User    " << user_name << endl;
    cout << "*****************************************************" << endl;
    cout << "             Use quit command to quit" << endl;
    cout << "-----------------------------------------------------" << endl;

    // 必须获取某一方的AES密钥之后才能进行文件的双向传输
    while (1) {
        cout << endl << "Use request or verify command to verify the key: ";
        string s;
        cin >> s;
        if (s == "request") {
            key_request(AcceptSocket);
            break;
        }
        else if (s == "verify") {
            key_verify(AcceptSocket);
            break;
        }
        else {
            cout << "Error request!! Please restart" << endl;
            continue;
        }
    }

    //----------------------
    // 创建两个线程，一个接受线程，一个发送线程
    HANDLE hThread[2];
    hThread[0] = CreateThread(NULL, 0, Recv, (LPVOID)&AcceptSocket, 0, NULL);
    hThread[1] = CreateThread(NULL, 0, Send, (LPVOID)&AcceptSocket, 0, NULL);

    WaitForMultipleObjects(2, hThread, TRUE, INFINITE);
    CloseHandle(hThread[0]);
    CloseHandle(hThread[1]);

    // 关闭服务端SOCKET
    iResult = closesocket(ListenSocket);
    if (iResult == SOCKET_ERROR) {
        cout << "Close failed with error: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    WSACleanup();
    return 0;
}
