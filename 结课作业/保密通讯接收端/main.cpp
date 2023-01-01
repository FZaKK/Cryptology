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
#define DEFAULT_BUFLEN 4096 // 2^12��С
#define MES_LEN sizeof(TCP_Message)
#define MAX_FILESIZE 1024 * 1024 * 10
//#define _WINSOCK_DEPRECATED_NO_WARNINGS 1  

using namespace std;

string quit_string = "quit";
int flag = 1;
unsigned int user_name = 0; // ������ɵ�0-99������������ڷַ���Կ����֤
long file_size = 0; // ÿ�η����ļ��Ĵ�С
const unsigned int START = 0;
const unsigned int SENDING = 1;
const unsigned int OVER = 2;
const unsigned int SPECIAL = 4; // ��������ʹ�ã��������ڻ�ȡ�ļ���С
const unsigned int KEY = 5;


class TCP_Message {
public:
    int send_state;
    int user;
    SYSTEMTIME timestamp;
    char buffer[DEFAULT_BUFLEN] = ""; // ��������
public:
    TCP_Message();
    TCP_Message(unsigned int state, unsigned int user_name, SYSTEMTIME time);
    TCP_Message(unsigned int state, unsigned int user_name, SYSTEMTIME time, string data_segment);
    void set_value(unsigned int state, unsigned int user_name, SYSTEMTIME time, char* data_segment, int size);  // ����һ��Ҫע��
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
    cout << temptime.wYear << "��" << temptime.wMonth << "��" << temptime.wDay << "��";
    cout << temptime.wHour << "ʱ" << temptime.wMinute << "��" << temptime.wSecond << "��" << endl;
    cout << "-----------------------------------------------------" << endl;
}

// Ŀǰ�����ڹ���·���²����������޸ĳɡ�/�����ļ�/��
// ������
void recv_file(SOCKET& RecvSocket) {
    char* file_content = new char[MAX_FILESIZE]; // ͵���ˣ�ֱ�ӵ���
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
                cout << "*** �ļ�����" << filename << endl;
                print_Recv_information(temp);
            }
            else if (temp.send_state == OVER) {
                // �ֵֹģ��ļ���������һ�����ݷ���
                memcpy(file_content + size, temp.buffer, file_size - size);
                size += file_size - size; // ??

                print_Recv_information(temp);
   
                ofstream fout(filename, ofstream::binary);
                fout.write(file_content, size); // ���ﻹ��size,���ʹ��string.data��c_str�Ļ�ͼƬ����ʾ�������������
                fout.close();
                temp_flag = false;

                cout << "*** �ļ���С��" << size << " bytes" << endl;
                cout << "-----*** �ɹ������ļ� ***-----" << endl << endl;

                cout << "�������������";
            }
            // �����ļ��Ĵ�С
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

        delete[] RecvBuf; // һ��Ҫdelete���������򲻸�������
    }
    delete[] file_content;
}

// ����ֵ���ERROR_CODE���ԣ�Ҫʹ��memcpy�����巢��ȥ
void send_packet(TCP_Message& Packet, SOCKET& SendSocket) {
    int iResult;
    char* SendBuf = new char[MES_LEN];

    memcpy(SendBuf, &Packet, MES_LEN);
    iResult = send(SendSocket, SendBuf, MES_LEN, 0);
    if (iResult == SOCKET_ERROR) {
        cout << "Sendto failed with error: " << WSAGetLastError() << endl;
    }

    if (Packet.send_state == START) {
        cout << "��ʼ�����ļ�..." << endl;
    }
    else if (Packet.send_state == SENDING) {
        cout << "���ڴ����ļ�..." << endl;
    }
    else if (Packet.send_state == SPECIAL) {
        cout << "�����ļ���С..." << endl;
    }
    else if (Packet.send_state == KEY) {
        cout << "���ڴ�����Կ..." << endl;
    }
    else {
        cout << "�����ļ�����..." << endl;
    }

    delete[] SendBuf;
}

string e_str, d_str, n_str;   // ��Կ{e, n}
string AES_Key = "00012001710198aeda79171460153594";
int real_AES_Key[4][4] = { 0 };
unsigned int other_user = -1; // �Է��û�������
bool key_verified = false; // !!

// ����˽Կ��ʹ��˽Կ���ܣ�����AES��Կ
// Ӧ����recvfile֮ǰ����key_verify���ٷ���һ���Է�user��ŵ���֤
void key_verify(SOCKET& SendSocket) {
    // ����RSA��Կ
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
            ofstream fout("�Է�RSA��Կ.txt");
            if (!fout) {
                cerr << "---*** �Է�RSA��Կ�洢ʧ�� ***---" << endl;
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

    ifstream fin("�Է�RSA��Կ.txt");
    if (!fin) {
        cerr << "---*** �Է�RSA��Կ��ȡʧ�� ***---" << endl;
    }
    fin >> e_str >> n_str;
    fin.close();
    // cout << e_str << endl;
    // cout << n_str << endl;
    BigInt e = BigInt(e_str.c_str());
    BigInt n = BigInt(n_str.c_str());

    // RSA��Կ����
    BigInt AES_mes = BigInt(AES_Key.c_str());
    BigInt AES_enc;
    AES_enc = Encrypt(AES_mes, e, n);
    cout << "AES Key: " << AES_enc.tostr() << endl;

    // ���Խ���
    /*
    ifstream fin1("RSA˽Կ.txt");
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

    cout << "��ͨ����Կ������֤�����ɹ�����AES��Կ" << endl;
    cout << "-----------------------------------------------------" << endl;
}

DWORD WINAPI Recv(LPVOID lparam_socket) {
    int recvResult;
    SOCKET* recvSocket = (SOCKET*)lparam_socket;  // һ��Ҫʹ��ָ���ͱ�������ΪҪָ��connect socket��λ��

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

// �����ԣ������̵߳ķ����ļ�
void send_file(string filename, SOCKET& SendSocket) {
    ifstream fin(filename.c_str(), ifstream::binary);

    // ��ȡ�ļ���С
    fin.seekg(0, std::ifstream::end);
    long size = fin.tellg();
    file_size = size;
    fin.seekg(0);
    char* binary_file_buf = new char[size];
    cout << " ** �ļ���С��" << size << " bytes" << endl;
    fin.read(&binary_file_buf[0], size);
    fin.close();

    // �������ݣ�ʱ������û� state->user->timestamp
    // ��һ�����ݰ�Ҫ�����ļ�����Header�ǲ���Ҫ��
    // ��Ҫ��ӱ����ļ����俪ʼ������ı�־
    SYSTEMTIME systime = { 0 };
    GetLocalTime(&systime);
    TCP_Message tcp_packets(START, user_name, systime, filename.c_str());

    // �������ݰ��ĸ������Լ����ݰ���size�����Զ����ݰ�����RSA����
    int packet_num = size / DEFAULT_BUFLEN + 1;
    cout << " ** �������ݰ���������" << packet_num << endl;

    send_packet(tcp_packets, SendSocket);

    // �����ļ���size
    // ����ն˷������һ�����ݷ���Ĵ�С
    int temp = size;
    cout << temp << endl;
    string tempbuf = to_string(temp);
    cout << tempbuf.c_str() << endl;

    GetLocalTime(&systime);
    TCP_Message size_packets(SPECIAL, user_name, systime, tempbuf.c_str());
    send_packet(size_packets, SendSocket);

    // ������һ���ļ����Լ�START��־�����һ�����ݰ���OVER��־���ְ�������
    for (int index = 0; index < packet_num; index++) {
        if (index == packet_num - 1) {
            GetLocalTime(&systime);
            tcp_packets.set_value(OVER, user_name, systime, binary_file_buf + index * DEFAULT_BUFLEN, size - index * DEFAULT_BUFLEN); // ?��
        }
        else {
            GetLocalTime(&systime);
            tcp_packets.set_value(SENDING, user_name, systime, binary_file_buf + index * DEFAULT_BUFLEN, DEFAULT_BUFLEN);
        }

        // ����Ҫ�������Ƕ�����
        send_packet(tcp_packets, SendSocket);
        cout << "user: " << tcp_packets.user << endl;
        cout << "state: " << tcp_packets.send_state << endl;
        cout << "time: ";
        SYSTEMTIME temptime = tcp_packets.timestamp;
        cout << temptime.wYear << "��" << temptime.wMonth << "��" << temptime.wDay << "��";
        cout << temptime.wHour << "ʱ" << temptime.wMinute << "��" << temptime.wSecond << "��" << endl;
        cout << "-----------------------------------------------------" << endl;
        Sleep(10);
    }

    cout << "-----*** �Է��ѳɹ������ļ���***----- " << endl << endl;
    delete[] binary_file_buf;
}

void key_request(SOCKET& SendSocket) {
    Sleep(100);

    ifstream fin1("RSA��Կ.txt");
    if (!fin1) {
        cerr << "---*** RSA��Կ��ȡʧ�� ***---" << endl;
    }
    fin1 >> e_str >> n_str;
    fin1.close();
    ifstream fin2("RSA˽Կ.txt");
    if (!fin2) {
        cerr << "---*** RSA˽Կ��ȡʧ�� ***---" << endl;
    }
    fin2 >> d_str >> n_str;
    fin2.close();

    BigInt e = BigInt(e_str.c_str());
    BigInt d = BigInt(d_str.c_str());
    BigInt n = BigInt(n_str.c_str());

    // ����RSA˽Կ������user��ź�ʱ���
    string private_key = e_str + '\n' + n_str;
    // cout << private_key << endl;
    SYSTEMTIME systime = { 0 };
    GetLocalTime(&systime);
    TCP_Message key_packets(KEY, user_name, systime, private_key.c_str());

    send_packet(key_packets, SendSocket);
    // �ȴ�������������к���Ϊ��֤
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
    // �ȴ�������Կ�ͶԷ������к�
    // ��֤ʱ����������
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

            // RSA����AES��Կ
            char AES_Key_enc[512] = "";
            for (int i = 0; i < strlen(temp.buffer); i++) {
                AES_Key_enc[i] = temp.buffer[i];
            }
            BigInt AES_enc = BigInt(AES_Key_enc);
            BigInt AES_dec;
            AES_dec = Decrypt(AES_enc, d, n);
            AES_Key = AES_dec.tostr();

            // ��AES Key�洢���ļ�֮�У�������һ�ε�ʹ��
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
            cout << verify_time.wYear << "��" << verify_time.wMonth << "��" << verify_time.wDay << "��";
            cout << verify_time.wHour << "ʱ" << verify_time.wMinute << "��" << verify_time.wSecond << "��" << endl;
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
            cout << "��֤��ʱ����" << endl;
        }
    }
    else {
        cout << "�û�����֤���󣡣�" << endl;
    }

    if (key_verified == true) {
        cout << "��ͨ����Կ������֤�����ɹ���ȡAES��Կ" << endl;
        cout << "-----------------------------------------------------" << endl;
    }
    else {
        cout << "��Կ������֤ʧ�ܣ������³���" << endl;
        cout << "-----------------------------------------------------" << endl;
    }
}

int cur_enc_text[4][4]; // AES����ʱ�Ĵ���

DWORD WINAPI Send(LPVOID lparam_socket) {

    // ������Ϣֱ��quit�˳�����
    // flagΪ�Ƿ��˳�����ı�־
    int sendResult;
    SOCKET* sendSocket = (SOCKET*)lparam_socket;

    while (1) {
        string command;
        cout << "�������������";
        cin >> command;
        cout << endl;
        if (command == "quit") {
            flag = 0;
            closesocket(*sendSocket);
            cout << endl << "�����Ͽ�����" << endl;
            return 1;
        }
        else if (command == "send") {
            cout << "��������Ҫ���͵��ļ���";
            string file;
            cin >> file;
            clock_t start = clock();
            send_file(file, *sendSocket);
            clock_t end = clock();
            cout << "**�����ļ�ʱ��Ϊ��" << (end - start) / CLOCKS_PER_SEC << "s" << endl;
            cout << "**������Ϊ:" << ((float)file_size) / ((end - start) / CLOCKS_PER_SEC) << " bytes/s " << endl << endl;
            continue;
        }
        // real_AES_Key
        else if (command == "encrypt") {
            // cur enc text��ʼ��
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    cur_enc_text[j][i] = 0;
                }
            }

            // ����AES��Կ
            ifstream fin("AESKey.txt");
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    fin >> hex >> real_AES_Key[j][i];
                }
            }
            fin.close();

            string filename;
            cout << "��������ҪAES���ܵ��ļ���";
            cin >> filename;

            // ��ȡ�ļ���С�������͵����ֻ��ͨ���ض����ļ�����ȡ������Ŀ
            // ������ʵ���ļ������Լ�padding��ʵ�鱨��
            ifstream fin0(filename, ifstream::binary);
            fin0.seekg(0, std::ifstream::end);
            long size = fin0.tellg();
            fin0.seekg(0);
            cout << "�ļ���С��" << size << " bytes" << endl;
            fin0.close();

            int group_num = size / 48;
            cout << "������Ŀ��" << group_num << endl;

            // ����������Ϊgroup num
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

            // �������
            for (int i = 0; i < 4 * group_num; i++) {
                for (int j = 0; j < 4; j++) {
                    if (to_enc[j][i] < 16)
                        cout << "0";
                    cout << hex << to_enc[j][i] << " ";
                }
            }
            cout << endl;

            // ��ʼ����
            for (int i = 0; i < group_num; i++) {
                // ��ʼ��������Ϊȫ1��ÿ�μ���ǰ����cur enc text
                for (int j = 4 * i; j < 4 * (i + 1); j++) {
                    for (int k = 0; k < 4; k++) {
                        cur_enc_text[k][j % 4] = to_enc[k][j] ^ cur_enc_text[k][j % 4];
                    }
                }
                Encode(cur_enc_text, real_AES_Key);
                // ȥ�������text��������ȥ
                for (int j = 4 * i; j < 4 * (i + 1); j++) {
                    for (int k = 0; k < 4; k++) {
                        to_enc[k][j] = cur_enc_text[k][j % 4];
                    }
                }
            }

            // �鿴���ܺ������
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

            // ����������ʹ���ļ���ʽ�洢�����ּ��ܴ������̵������ԣ�Ҳ����ֱ�Ӽ�����ʹ���
            // ����ļ���Ҳ�ܹ������Ż����ɲ�����
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
            // cur enc text��ʼ��
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    cur_enc_text[j][i] = 0;
                }
            }

            // ����AES��Կ
            ifstream fin("AESKey.txt");
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    fin >> hex >> real_AES_Key[j][i];
                }
            }
            fin.close();

            string filename;
            cout << "��������ҪAES���ܵ��ļ���";
            cin >> filename;

            // ��ȡ�ļ���С�������͵����ֻ��ͨ���ض����ļ�����ȡ������Ŀ
            // ������ʵ���ļ������Լ�padding��ʵ�鱨��
            ifstream fin0(filename, ifstream::binary);
            fin0.seekg(0, std::ifstream::end);
            long size = fin0.tellg();
            fin0.seekg(0);
            cout << "�ļ���С��" << size << " bytes" << endl;
            fin0.close();

            int group_num = size / 48;
            cout << "������Ŀ��" << group_num << endl;

            // ��ʼ���ܲ��洢Ϊ�ļ�����ʽ
            // ��ʼ������ʱ��һ�ε�4*4������
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

            // �������
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
                // ��ʼ��������Ϊȫ1��ÿ�μ���ǰ����cur enc text
                int temp[4][4] = { 0 };
                for (int j = 4 * i; j < 4 * (i + 1); j++) {
                    for (int k = 0; k < 4; k++) {
                        cur_enc_text[k][j % 4] = to_dec[k][j];
                        temp[k][j % 4] = to_dec[k][j];
                    }
                }
                Decode(cur_enc_text, real_AES_Key);
                // ȥ�������text��������ȥ
                for (int j = 4 * i; j < 4 * (i + 1); j++) {
                    for (int k = 0; k < 4; k++) {
                        to_dec[k][j] = cur_enc_text[k][j % 4] ^ last_enc[k][j % 4];
                    }
                }
                // ����last encҲ���Ǹ�����һ�ε�����
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

            // �洢�����ļ�
            // ͬ�������ļ������Խ����Ż�
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
    // ����û����
    srand((unsigned)time(NULL));
    user_name = rand() % 100;

    //----------------------
    // ��ʼ��Winsock
    WSADATA wsaData;
    int iResult;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        cout << "WSAStartup failed with error: " << iResult << endl;
        return 1;
    }

    //----------------------
    // ����һ��������SOCKET
    // �����connect��������´���һ���߳�
    SOCKET ListenSocket;
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET) {
        cout << "Socket failed with error: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    //----------------------
    // ����bind�����󶨵�IP��ַ�Ͷ˿ں�
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
    // �������������������ź�
    if (listen(ListenSocket, 5) == SOCKET_ERROR) {
        cout << "Listen failed with error: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    //----------------------
    // �ȴ�����
    cout << "Waiting for client to connect..." << endl;

    sockaddr_in addrClient;
    int len = sizeof(sockaddr_in);
    // ���ܳɹ�������clientͨѶ��Socket
    SOCKET AcceptSocket = accept(ListenSocket, (SOCKADDR*)&addrClient, &len);
    if (AcceptSocket == INVALID_SOCKET) {
        cout << "Accept failed with error: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    cout << "okkk zzekun" << endl;
    // ��ӡ��������ı�־
    cout << "              Welcome    User    " << user_name << endl;
    cout << "*****************************************************" << endl;
    cout << "             Use quit command to quit" << endl;
    cout << "-----------------------------------------------------" << endl;

    // �����ȡĳһ����AES��Կ֮����ܽ����ļ���˫����
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
    // ���������̣߳�һ�������̣߳�һ�������߳�
    HANDLE hThread[2];
    hThread[0] = CreateThread(NULL, 0, Recv, (LPVOID)&AcceptSocket, 0, NULL);
    hThread[1] = CreateThread(NULL, 0, Send, (LPVOID)&AcceptSocket, 0, NULL);

    WaitForMultipleObjects(2, hThread, TRUE, INFINITE);
    CloseHandle(hThread[0]);
    CloseHandle(hThread[1]);

    // �رշ����SOCKET
    iResult = closesocket(ListenSocket);
    if (iResult == SOCKET_ERROR) {
        cout << "Close failed with error: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    WSACleanup();
    return 0;
}
