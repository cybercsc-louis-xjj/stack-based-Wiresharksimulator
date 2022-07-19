#include <bits/stdc++.h>
#include <pcap.h>
#include <winsock2.h>
#include "pheader.h"
using namespace std;

string changeCharToString(unsigned char p)
{

 string str="";
 str+=p;
 return str;

}
string to_string(int str){
    stringstream ss;
    ss<<str;
    return ss.str();
}
string IpToString(ip_address ip_addr){
    string tp="";
    for(int i=0;i<4;i++){
        if(i!=0)tp+=".";
        tp+=to_string((int)(ip_addr.byte[i]));
    }
    return tp;
}

int get_cer_len(u_char* cer_len_hd){
    int len=0;
    for(int i=0;i<3;i++)
        len+=((int)cer_len_hd[i])<<8*(2-i);
    return len;
}
//打印证书信息
int print_certificate(string cer_name,int cer_len){
    //由于windows没有自带openssl库,而下载的开发库缺少链接文件,所以只能用命令行直接打印
    string tp="openssl x509 -in "+cer_name+" -inform der -text -noout";
    char *szCmd=(char*)tp.c_str();
    system(szCmd);
    return 0;
}

//重组证书分片
void reassemble(vector<pdu_hd> pdus,FILE* fp,int id){
    int cer_len=0,len_tp=0;
    for(int i=0;i<pdus.size();i++)cer_len+=pdus[i].payload_len;
    u_char *pdu_thd=(u_char*)malloc(sizeof(u_char)*cer_len);//这里内存分配格外注意
    //利用ack号排序，处理乱序包
    sort(pdus.begin(),pdus.end());
    //对于排序后的结构体，逐个将负载写入一段连续内存，拼接成完整证书信息(尾部还有其他tls头)
    //cout<<"pdus_size:"<<pdus.size()<<endl;
    for(int i=0;i<pdus.size();i++){
        fseek(fp,pdus[i].payload_hd,SEEK_SET);
        fread(pdu_thd+len_tp,pdus[i].payload_len,1,fp);
        len_tp+=pdus[i].payload_len;
    }

    u_char* certi_hd=pdu_thd+12;
    //获取证书总长(包含各个证书的长度字段)
    int cer_tlen=get_cer_len(pdu_thd+9),tp_cum_tlen=0,tp_tlen;
    //cout<<"len_tp:"<<cer_tlen<<endl;
    while(cer_tlen-tp_cum_tlen>0){
        //各个证书分别的长度
        tp_tlen=get_cer_len(certi_hd);
        string cer_name="tmp"+to_string(id)+".der";
        //写入文件
        FILE* fder=fopen(cer_name.c_str(),"wb");
        fwrite(certi_hd+3,sizeof(u_char)*tp_tlen,1,fder);
        fclose(fder);
        print_certificate(cer_name,tp_tlen);
        certi_hd+=tp_tlen+3;
        tp_cum_tlen+=tp_tlen+3;
        //如果实际长度小于标志位给出的长度，说明传输过程中丢包或者包不完整,这种情况就无能为力了
        if(cer_tlen<tp_cum_tlen){
            cout<<"error: packet loss"<<endl;
            break;
        }

    }
    free(pdu_thd);
    return ;
}



int fields_len=3;
string fields[3]={"Host","User-Agent","GET"};
map<string,vector<pdu_hd> > dic;
map<u_int,bool> ack_list;//ack号管理

void tls_parse(const u_char*,ip_header*,long,FILE*,int);

void http_parse(ip_header*,u_char*);

int main(int argc, char *argv[]) {
    char errbuf[100];
    pcap_t *pfile = pcap_open_offline("battlefield_android_filtered.pcap", errbuf);
    if (NULL == pfile) {
        printf("%s\n", errbuf);
        return -1;
    }
    pcap_pkthdr *pkthdr = 0;
    const u_char *pkt_data = 0;
    int cou=0,res;
    long pkt_offset=24,pkt_hd;
    ether_header * eheader=(ether_header*)malloc(sizeof(ether_header));
    ip_header * ih=(ip_header*)malloc(sizeof(ip_header));
    //避免遇到控制字符而导致无法继续读入内容,所以打开方式用rb
    FILE *fp=fopen("battlefield_android_filtered.pcap","rb");

    while(fseek(fp,pkt_offset,SEEK_SET)==0){
    //while(res=(pcap_next_ex(pfile, &pkthdr, &pkt_data))>=0){
        res=pcap_next_ex(pfile, &pkthdr, &pkt_data);
        pkt_hd=pkt_offset+16;
        cou++;
        //cout<<cou<<endl;
        pkt_offset+=pkthdr->caplen+16;
        //cout<<endl<<cou<<endl;
        if(res == 0)continue; /* read time out*/
        ether_header * eheader = (ether_header*)pkt_data; /* transform packet data to ethernet header */
        if(eheader->ether_type == htons(ETHERTYPE_IP)) { /* ip packet only */
            ip_header * ih = (ip_header*)(pkt_data+14); /* get ip header */
            if(ih->proto == htons(TCP_PROTOCAL)) { /* tcp packet only */
                    //int ip_len = ntohs(ih->tlen); /* get ip length, it contains header and body */
                    int find_http = false;
                    char* ip_pkt_data = (char*)ih;
                    int n = 0;
                    char buffer[BUFFER_MAX_LENGTH];
                    tcp_header * th = (tcp_header*)(pkt_data+34);
                    int sport=ntohs(th->th_sport),dport=ntohs(th->th_dport),tcp_flags=th->flags;
                    int tcp_hdlen=((int)th->th_len)>>2;
                    if(tcp_hdlen+34>=pkthdr->caplen)continue;
                    if(tcp_flags==0x18||tcp_flags==0x10){//同时考虑 client hello 和 server hello
                        //http
                        if(dport==80){
                            cout<<endl;
                            cout<<"pkt"<<cou<<":"<<"http"<<endl;
                            http_parse(ih,(u_char*)th+tcp_hdlen);
                        }
                        //https
                        if(dport==443||sport==443){

                            tls_parse(pkt_data,ih,pkt_hd,fp,cou);
                        }
                    }
            }
        }
        if(cou>9000)break;
    }
    pcap_close(pfile);
    return 0;
}

void tls_parse(const u_char* pkt_data, ip_header* ih,long pkt_hd,FILE* fp,int cou){
    tcp_header * th = (tcp_header*)(pkt_data+34);
    int tcp_hdlen=((int)th->th_len)>>2,ip_hdlen=(int)((ih->ver_ihl)&0x0f)<<2;
    //windows
    int sport=ntohs(th->th_sport),dport=ntohs(th->th_dport),tcp_flags=th->flags;
    u_char *tls_type=(u_char*)(pkt_data+34+tcp_hdlen);
    u_char *hs_type=(u_char*)(tls_type+5);
    u_int ack_cer=(u_int)ntohl(th->th_ack),seq_cer=(u_int)ntohl(th->th_seq);
    int ih_tlen=(int)ntohs(ih->tlen);
    //针对server hello done,要确定重组分片的结束位置
    u_char *tls_tail=(u_char*)ih+ih_tlen-9;
    //handshake
    if((int)(tls_type[0])==22){
        u_short *tls_hd_len=(u_short*)(tls_type+3);
        int tls_len=(int)ntohs(*tls_hd_len);

        //client hello,包括cipher_suites,server_name(SNI)
        if((int)hs_type[0]==1){
            cout<<endl;
            cout<<"pkt"<<cou<<":"<<"tls_handshake"<<endl<<"client_hello"<<endl;
            tls_hs_hd *tls_hs_h=(tls_hs_hd*)(tls_type+5);
            int pad_len=sizeof(*tls_hs_h)/sizeof(u_char);
            u_char *sid_len=(u_char*)tls_hs_h+pad_len;
            pad_len+=(int)*sid_len+1;
            u_short *cipher_hd=(u_short*)((u_char*)tls_hs_h+pad_len);
            int cipher_len=ntohs(cipher_hd[0]);
            for(int i=1;i<=cipher_len/2;i++){
                char suite_tp[16]={0};
                sprintf(suite_tp,"%#06x",ntohs(cipher_hd[i]));
                cout<<"cipher_suite"<<i<<":"<<suite_tp<<endl;
            }
            pad_len+=cipher_len+2;//长度占两个
            u_char *method=(u_char*)tls_hs_h+pad_len;
            pad_len+=(int)*method+1+2;//跳过一个长度
            ext_hd* ext;
            int extype=-1,exlen=0;
            while(extype!=21&&extype!=0){
                pad_len+=exlen;
                ext=(ext_hd*)((u_char*)tls_hs_h+pad_len);
                extype=(int)ntohs(ext->ext_type);
                exlen=(int)ntohs(ext->ext_len);
                pad_len+=sizeof(ext_hd)/sizeof(u_char);//+(int)ntohs(ext->ext_len);
            }
            if(extype==21)
                cout<<"No SNI"<<endl;
            else{
                //cout<<"SNI"<<endl;
                u_char *sni=(u_char*)tls_hs_h+pad_len;//还是对齐问题
                u_short sni_len=*(u_short*)(sni+3);
                u_char *sni_str=sni+5;
                string tpp="";
                for(bpf_u_int32 i=0;i<(int)ntohs(sni_len);i++){
                    //printf("%c",sni_str[i]);
                    tpp=tpp+changeCharToString(sni_str[i]);
                }
                cout<<"server name:"<<tpp<<endl;
            }
        }
        //server hello 会包含部分证书数据的分片，并且是整个证书的开始位置
        if((int)hs_type[0]==2){
            cout<<endl;
            cout<<"pkt"<<cou<<":"<<"tls_handshake"<<endl<<"server_hello"<<endl;
            //用四元组作为标识(因为协议字段已经利用if else判断过了，所以不用五元组)
            string key=IpToString(ih->saddr)+IpToString(ih->daddr)+to_string(sport)+to_string(dport);
            //每条流只有一个证书，对应多个segments of PDU
            //每个伪分片需要记录：
            //数据开始位置(对于server hello来说，需要去掉包括tls头部在内的所有上层头部，因为tls的头部也包含在tcp负载中)
            //数据长度
            //seq号(用于乱序整理)
            dic[key].push_back(pdu_hd{pkt_hd+34+tcp_hdlen+5+tls_len,ih_tlen-20-5-tcp_hdlen-tls_len,seq_cer});
            //同时还要记录这些组成证书的报文的ack号，因为伪分片的ack是一样的
            ack_list.insert({ack_cer,true});
            if(*tls_tail==0x16&&*(tls_tail+5)==0x0e){
                cout<<"server hello done"<<endl;
                //当捕获到的流量协议的MTU较大,也可能存在一个报文包含所有第二阶段的握手信息的情况
                reassemble(dic[key],fp,cou);
                //重组完成后删掉相应键值对
                dic.erase(key);
            }
        }
    }
    //certificate segment of PDU(针对server hello done 报文, 以及不包含tls头部的tcp证书分片报文)
    else if(sport==443&&ack_list.find(ack_cer)!=ack_list.end()){
        string key=IpToString(ih->saddr)+IpToString(ih->daddr)+to_string(sport)+to_string(dport);
        pdu_hd pre_hd=dic[key][0];
        u_char *pdu_test=(u_char*)malloc(sizeof(u_char));
        fseek(fp,pre_hd.payload_hd,SEEK_SET);
        fread(pdu_test,sizeof(u_char),1,fp);
        //从尾部寻找server hello done的tls头部
        cout<<endl;
        cout<<"pkt"<<cou<<":"<<"tls";
        if(*tls_tail==0x16&&*(tls_tail+5)==0x0e){
            cout<<"_handshake"<<endl<<"server hello done"<<endl;
            //和 server hello不一样
            dic[key].push_back(pdu_hd{pkt_hd+34+tcp_hdlen,ih_tlen-20-tcp_hdlen,seq_cer});
            //server hello done也意味着证书协商的结束,可以开始重组证书
            reassemble(dic[key],fp,cou);
            //重组完成后删掉相应键值对
            dic.erase(key);
        }
        else{
            cout<<endl<<"pdu_tcp"<<endl;
            dic[key].push_back(pdu_hd{pkt_hd+34+tcp_hdlen,ih_tlen-20-tcp_hdlen,seq_cer});
        }
    }
}

void http_parse(ip_header* ih,u_char* tcp_pl){
    int ip_len = ntohs(ih->tlen),ip_hdlen=(int)((ih->ver_ihl)&0x0f)<<2;;
    int http_len=ip_len-20-ip_hdlen;
    u_char tp_u[http_len]={0};
    char tp_c[http_len];
    memcpy(tp_u,tcp_pl,sizeof(tp_u));
    string tpp="";
    for(bpf_u_int32 i=0;i<http_len;i++){
        tpp=tpp+changeCharToString(tp_u[i]);
    }
    for(int i=0;i<fields_len;i++){
        int field_pos=tpp.find(fields[i],0);
        string end_str="\r\n";
        int end_field_pos=tpp.find_first_of(end_str,field_pos);
        if(field_pos!=-1){
            if(fields[i]=="GET"){
                end_field_pos-=9;
                field_pos+=4;
                cout<<"URL"<<":";
            }
            cout<<tpp.substr(field_pos,end_field_pos-field_pos)<<endl;
        }
        else{
            cout<<"No field "<<fields[i]<<endl;
        }
    }

}

